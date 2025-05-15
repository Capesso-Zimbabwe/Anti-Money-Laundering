from django.apps import AppConfig


class TransactionMonitoringConfig(AppConfig):
    name = 'transaction_monitoring'
    verbose_name = 'Transaction Monitoring System'
    
    def ready(self):
        """
        Import signals when the app is ready.
        """
        import transaction_monitoring.signals
