from django import template
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

register = template.Library()

@register.filter(name='add_months')
def add_months(date_str, months):
    """Add a specified number of months to a date string"""
    try:
        if isinstance(date_str, str):
            date_obj = datetime.strptime(date_str, '%d %b %Y')
        else:
            date_obj = date_str
            
        # Add months
        new_date = date_obj + relativedelta(months=int(months))
        # Return in the same format
        return new_date.strftime('%d %b %Y')
    except (ValueError, TypeError):
        return date_str
    
@register.filter(name='add_year')
def add_year(date_str, years):
    """Add a specified number of years to a date string"""
    try:
        if isinstance(date_str, str):
            date_obj = datetime.strptime(date_str, '%d %b %Y')
        else:
            date_obj = date_str
            
        # Add years
        new_date = date_obj + relativedelta(years=int(years))
        # Return in the same format
        return new_date.strftime('%d %b %Y')
    except (ValueError, TypeError):
        return date_str 