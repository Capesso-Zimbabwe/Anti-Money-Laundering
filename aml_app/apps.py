from django.apps import AppConfig


class AmlAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'aml_app'

    def ready(self):
        """Import signals when Django starts"""
        import aml_app.signals  # Import signals to register them

    


