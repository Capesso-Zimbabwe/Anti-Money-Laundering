from django import template
register = template.Library()

@register.filter
def dict_get(dictionary, key):
    """
    Access a dictionary value using a key in a template.
    
    Usage:
        {{ some_dict|dict_get:'key_name' }}
    
    Args:
        dictionary: The dictionary to access
        key: The key to lookup
        
    Returns:
        The value for the key or None if the key does not exist
    """
    if dictionary is None:
        return None
        
    if isinstance(dictionary, dict):
        return dictionary.get(key)
    
    return None 