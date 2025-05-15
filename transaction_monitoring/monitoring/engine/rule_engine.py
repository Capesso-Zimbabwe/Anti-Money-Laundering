from typing import Dict, List, Any, Optional
import logging
import functools
import concurrent.futures
from threading import Lock
import time

from ..rules.base_rule import BaseRule
from ..utils.log_utils import log_rule_triggered, log_error

logger = logging.getLogger(__name__)

class RuleEngine:
    """
    Core rule evaluation engine.
    
    This engine manages the evaluation of rules against transactions
    and calculates risk scores.
    """
    
    def __init__(self, scoring_engine=None, max_workers=10, enable_caching=True, cache_ttl=300):
        """
        Initialize the rule engine.
        
        Args:
            scoring_engine: Optional scoring engine instance
            max_workers: Maximum number of concurrent workers for parallel rule evaluation
            enable_caching: Whether to enable rule result caching
            cache_ttl: Cache time-to-live in seconds
        """
        self.rules = []
        self.scoring_engine = scoring_engine
        self.max_workers = max_workers
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        self.rule_cache = {}
        self.cache_lock = Lock()
        
        # Statistics tracking
        self.stats = {
            'total_evaluations': 0,
            'cache_hits': 0,
            'rules_triggered': 0,
            'evaluation_time': 0,
            'last_reset': time.time()
        }
    
    def register_rule(self, rule: BaseRule) -> None:
        """
        Register a rule with the engine.
        
        Args:
            rule: The rule to register
        """
        self.rules.append(rule)
        logger.info(f"Registered rule: {rule.rule_id} - {rule.rule_name}")
    
    def unregister_rule(self, rule_id: str) -> None:
        """
        Unregister a rule from the engine.
        
        Args:
            rule_id: The ID of the rule to unregister
        """
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        logger.info(f"Unregistered rule: {rule_id}")
        
        # Clear the cache when rules change
        self._clear_cache()
    
    def evaluate_transaction(self, transaction: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a transaction against all registered rules.
        
        Args:
            transaction: The transaction to evaluate
            context: Additional context needed for rule evaluation
            
        Returns:
            List of dictionaries containing rule results and scores
        """
        start_time = time.time()
        self.stats['total_evaluations'] += 1
        
        # Get active rules that apply to this transaction type
        applicable_rules = self._get_applicable_rules(transaction)
        
        # If parallel processing is enabled and there are multiple rules, use it
        if self.max_workers > 1 and len(applicable_rules) > 1:
            results = self._evaluate_parallel(applicable_rules, transaction, context)
        else:
            results = self._evaluate_sequential(applicable_rules, transaction, context)
        
        # Update statistics
        self.stats['evaluation_time'] += (time.time() - start_time)
        self.stats['rules_triggered'] += len(results)
        
        return results
    
    def _evaluate_sequential(self, rules: List[BaseRule], transaction: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate rules sequentially.
        
        Args:
            rules: List of rules to evaluate
            transaction: The transaction to evaluate
            context: Additional context
            
        Returns:
            List of results
        """
        results = []
        
        for rule in rules:
            try:
                result = self._evaluate_single_rule(rule, transaction, context)
                if result:
                    results.append(result)
            except Exception as e:
                log_error(
                    logger, 
                    f"Error evaluating rule {rule.rule_id}", 
                    exception=e,
                    context={'transaction_id': transaction.transaction_id}
                )
        
        return results
    
    def _evaluate_parallel(self, rules: List[BaseRule], transaction: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate rules in parallel using a thread pool.
        
        Args:
            rules: List of rules to evaluate
            transaction: The transaction to evaluate
            context: Additional context
            
        Returns:
            List of results
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all rule evaluations to the thread pool
            future_to_rule = {
                executor.submit(self._evaluate_single_rule, rule, transaction, context): rule
                for rule in rules
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_rule):
                rule = future_to_rule[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    log_error(
                        logger, 
                        f"Error evaluating rule {rule.rule_id}", 
                        exception=e,
                        context={'transaction_id': transaction.transaction_id}
                    )
        
        return results
    
    def _evaluate_single_rule(self, rule: BaseRule, transaction: Any, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single rule, with caching if enabled.
        
        Args:
            rule: The rule to evaluate
            transaction: The transaction to evaluate
            context: Additional context
            
        Returns:
            Result dictionary or None if rule didn't trigger
        """
        # Check cache if enabled
        if self.enable_caching:
            cache_key = self._get_cache_key(rule.rule_id, transaction.transaction_id)
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                self.stats['cache_hits'] += 1
                return cached_result
        
        try:
            # Evaluate the rule
            triggered, details = rule.evaluate(transaction, context)
            
            if triggered:
                # Calculate the risk score
                score = self.scoring_engine.calculate_score(rule, transaction, details)
                
                # If score exceeds threshold, add to results
                if score >= self.scoring_engine.get_minimum_alert_score():
                    result = {
                        'rule': rule.get_rule_info(),
                        'score': score,
                        'details': details
                    }
                    
                    # Log the rule trigger
                    log_rule_triggered(
                        logger,
                        rule.rule_id,
                        transaction.transaction_id,
                        score,
                        details
                    )
                    
                    # Cache the result if caching is enabled
                    if self.enable_caching:
                        self._add_to_cache(cache_key, result)
                    
                    return result
            
            # If we reach here, either the rule didn't trigger or the score was too low
            if self.enable_caching:
                # Cache negative result too
                self._add_to_cache(cache_key, None)
            
            return None
        
        except Exception as e:
            log_error(
                logger,
                f"Error evaluating rule {rule.rule_id}",
                exception=e,
                context={'transaction_id': transaction.transaction_id}
            )
            raise
    
    def _get_applicable_rules(self, transaction: Any) -> List[BaseRule]:
        """
        Get rules that apply to this transaction type.
        
        Args:
            transaction: The transaction
            
        Returns:
            List of applicable rules
        """
        transaction_type = getattr(transaction, 'transaction_type_code', None)
        return [
            rule for rule in self.rules
            if rule.enabled and rule.matches_transaction_type(transaction_type)
        ]
    
    def _get_cache_key(self, rule_id: str, transaction_id: str) -> str:
        """
        Generate a cache key for a rule-transaction pair.
        
        Args:
            rule_id: The rule ID
            transaction_id: The transaction ID
            
        Returns:
            Cache key string
        """
        return f"{rule_id}:{transaction_id}"
    
    def _get_from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get a result from the cache.
        
        Args:
            key: The cache key
            
        Returns:
            Cached result or None if not found or expired
        """
        with self.cache_lock:
            if key in self.rule_cache:
                entry = self.rule_cache[key]
                if time.time() - entry['timestamp'] < self.cache_ttl:
                    return entry['result']
                else:
                    # Expired entry
                    del self.rule_cache[key]
            return None
    
    def _add_to_cache(self, key: str, result: Optional[Dict[str, Any]]) -> None:
        """
        Add a result to the cache.
        
        Args:
            key: The cache key
            result: The result to cache
        """
        with self.cache_lock:
            self.rule_cache[key] = {
                'result': result,
                'timestamp': time.time()
            }
    
    def _clear_cache(self) -> None:
        """Clear the rule cache."""
        with self.cache_lock:
            self.rule_cache.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['uptime'] = time.time() - stats['last_reset']
        
        # Calculate derived statistics
        if stats['total_evaluations'] > 0:
            stats['cache_hit_rate'] = stats['cache_hits'] / stats['total_evaluations']
            stats['trigger_rate'] = stats['rules_triggered'] / stats['total_evaluations']
            stats['avg_evaluation_time'] = stats['evaluation_time'] / stats['total_evaluations']
        else:
            stats['cache_hit_rate'] = 0
            stats['trigger_rate'] = 0
            stats['avg_evaluation_time'] = 0
        
        stats['cache_size'] = len(self.rule_cache)
        stats['rules_count'] = len(self.rules)
        stats['enabled_rules_count'] = len([r for r in self.rules if r.enabled])
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset the engine statistics."""
        self.stats = {
            'total_evaluations': 0,
            'cache_hits': 0,
            'rules_triggered': 0,
            'evaluation_time': 0,
            'last_reset': time.time()
        }

    def evaluate_rule_combinations(self, transaction, individual_results):
        # Look for patterns across multiple rules
        if 'AML-LCT' in triggered_rules and 'AML-ADR' in triggered_rules:
            # Large cash transactions in a dormant account - high risk combination
            return combined_score * 1.5  # Apply multiplier for combined patterns
