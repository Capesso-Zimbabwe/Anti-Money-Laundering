# Transaction Monitoring System

A comprehensive transaction monitoring system for detecting suspicious financial activities and ensuring AML compliance.

## Architecture

The system is built with a modular, microservices-oriented architecture:

- **Core Engine**: Rule-based evaluation system with parallel processing capabilities
- **API Layer**: RESTful API for all operations
- **Machine Learning**: Anomaly detection for identifying unusual patterns
- **Dashboard**: Real-time monitoring and statistics visualization
- **Alert Management**: Workflow for handling and investigating alerts

## Features

- **Rule Engine**
  - Configurable rules with thresholds and parameters
  - Parallel rule evaluation for improved performance
  - Caching system for repeat evaluations
  - Real-time performance metrics

- **Transaction Processing**
  - Batch processing of transactions
  - Real-time processing capability
  - Transaction context enrichment
  - Optimized database operations

- **Alert Management**
  - Risk scoring system
  - Alert workflow (creation, review, closure)
  - SAR reporting integration
  - Documentation and evidence collection

- **Machine Learning Integration**
  - Anomaly detection models
  - Feature extraction from transaction data
  - Model training and evaluation pipeline
  - Continuous learning capabilities

- **Monitoring Dashboard**
  - Real-time statistics
  - Alert visualization
  - Rule performance metrics
  - System health monitoring

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure the database in settings.py
4. Run migrations:
   ```
   python manage.py migrate
   ```
5. Start the development server:
   ```
   python manage.py runserver
   ```

## Usage

### API Endpoints

The system provides the following API endpoints:

- `/api/v1/transactions/` - Transaction management
- `/api/v1/alerts/` - Alert management
- `/api/v1/reports/` - SAR reports
- `/api/v1/rules/` - Rule configuration
- `/api/v1/stats/engine/` - Engine statistics

### Web Interface

Access the following URLs in your browser:

- `/dashboard/` - Main monitoring dashboard
- `/alerts/` - List of suspicious transactions
- `/reports/` - SAR reports
- `/rules/` - Rule management

## Configuration

Rules can be configured in the database or through the API. Each rule includes:

- Thresholds and parameters
- Transaction types to monitor
- Recurrence settings
- Risk scoring algorithm

## Development

### Running Tests

```
pytest
```

### Code Quality

```
flake8
black .
isort .
```

## Performance Considerations

- Use Redis for caching frequent operations
- Configure parallel processing based on your hardware capabilities
- Consider database indexing for large transaction volumes
- Use Celery for background task processing

## Security Considerations

- Implement proper authentication and authorization
- Encrypt sensitive data
- Validate and sanitize all inputs
- Follow security best practices for financial applications

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Rule Configuration System

The system includes a flexible rule configuration framework that allows administrators to:

1. **Select Rule Types**: Choose from predefined rule types such as Dormant Account Activity and Large Cash Transactions.

2. **Configure Parameters**: Each rule type has specific configurable parameters that control its behavior:
   - Dormant Account Rule: Account age threshold, inactivity period, etc.
   - Large Cash Rule: Transaction amount threshold, currency, etc.

3. **Set Scoring Thresholds**: Configure scoring thresholds for various factors like transaction amount and recurrence.

4. **Specify Transaction Types**: Select which transaction types the rule applies to.

### Rule Implementation

Rules are implemented as Python classes that:
- Define specific detection logic in the `evaluate()` method
- Inherit from a common `BaseRule` abstract base class
- Provide default parameter values that can be overridden via the UI

The rule configuration UI is available at `/rules/{rule_id}/config/` and allows administrators to:
1. Configure basic rule settings (name, description, etc.)
2. Select and configure a rule type
3. Set scoring thresholds and parameters
4. Enable/disable the rule

### Technical Details

The system uses:
- A Rule Registry that maps rule types to implementation classes
- JSON storage for rule-specific parameters
- Dynamic form generation based on rule type
- A monitoring service that manages rule evaluation 