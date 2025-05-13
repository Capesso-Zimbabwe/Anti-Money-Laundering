/**
 * This is a minimal config.
 *
 * If you need the full config, get it from here:
 * https://unpkg.com/browse/tailwindcss@latest/stubs/defaultConfig.stub.js
 */

module.exports = {
    content: [
      /**
       * HTML. Paths to Django template files that will contain Tailwind CSS classes.
       */
  
      /*  Templates within theme app (<tailwind_app_name>/templates), e.g. base.html. */
      '../templates/**/*.html',
  
      /* JS files in your theme app */
      '../templates/**/*.js',
      '../../templates/**/*.js',
  
      /* Python files if you use Tailwind classes there */
      '../../**/*.py',
  
      /*
       * Main templates directory of the project (BASE_DIR/templates).
       */
      '../../templates/**/*.html',
  
      /*
       * Templates in other django apps (BASE_DIR/<any_app_name>/templates).
       */
      '../../**/templates/**/*.html',
  
      /**
       * (Optional) Uncomment to process JS in other places:
       */
      // '!../../**/node_modules',
      // '../../**/*.js',
  
      /**
       * (Optional) Uncomment to process Python in other places:
       */
      // '../../**/*.py'
    ],
  
    theme: {
      extend: {
        fontFamily: {
          montserrat: ['Montserrat', 'sans-serif'],
        },
      },
    },
  
    plugins: [
      /**
       * Minimal form styles:
       */
      require('@tailwindcss/forms'),
  
      /**
       * Beautiful typography defaults:
       */
      require('@tailwindcss/typography'),
  
      /**
       * Aspect-ratio utilities:
       */
      require('@tailwindcss/aspect-ratio'),
    ],
  }
  