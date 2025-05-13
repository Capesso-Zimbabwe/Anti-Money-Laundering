from django import template

register = template.Library()

@register.filter(name='highlight_error')
def highlight_error(field):
    """Add error styling to form fields if they have errors"""
    css_classes = field.field.widget.attrs.get('class', '')
    
    if field.errors:
        if 'border-red-500' not in css_classes:
            css_classes += ' border-red-500 bg-red-50'
        
        # Add data attribute with error message for JavaScript use
        error_msg = field.errors[0] if field.errors else ''
        field.field.widget.attrs['data-error'] = error_msg
    
    field.field.widget.attrs['class'] = css_classes
    return field

@register.simple_tag(name='field_error')
def field_error(field):
    """Return the field error message if it exists, otherwise empty string"""
    return field.errors[0] if field.errors else '' 