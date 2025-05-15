from django import template

register = template.Library()

@register.filter
def dict_get(dictionary, key):
    """
    Get a value from a dictionary by key in a Django template
    Usage: {{ my_dict|dict_get:key_name }}
    """
    if not dictionary:
        return None
    
    if isinstance(dictionary, dict):
        return dictionary.get(key)
    
    return None 