# Organización de Assets del Logo

Esta carpeta contiene el logo oficial de VenridesScreenS.

## Uso

El logo actual (`logo.png`) es utilizado por el componente `OfficialLogo.jsx` en toda la aplicación.

## Cambiar el Logo

Para actualizar el logo en toda la aplicación:

1. Reemplaza el archivo `logo.png` en esta carpeta con tu nuevo logo
2. Asegúrate de que el nuevo logo tenga:
   - Fondo transparente (formato PNG con canal alpha)
   - Dimensiones similares al logo actual (recomendado: ~200x57 píxeles)
3. Los cambios se reflejarán automáticamente en toda la aplicación

## Dimensiones Optimizadas

El componente `OfficialLogo.jsx` está optimizado para mantener las proporciones correctas del logo independientemente de su tamaño original, usando:
- `height: 100%` para llenar el contenedor
- `width: auto` para mantener proporciones
- `object-fit: contain` para evitar distorsión

Esto garantiza que cualquier logo que coloques aquí se verá con las mismas dimensiones visuales que el actual.
