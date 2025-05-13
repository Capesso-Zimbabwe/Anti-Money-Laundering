from aml_app.models import Alert


def open_alert_count(request):
    """
    Returns a dict with the number of unresolved alerts.
    If the user is not authenticated, returns 0 or skip if you like.
    """
    if request.user.is_authenticated:
        count = Alert.objects.filter(status="OPEN").count()
    else:
        count = 0

    return {'open_alert_count': count}