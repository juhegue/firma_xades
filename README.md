# firma_xades
Firma electrónica formato facturae v3.1

* Se puede ejecutar desde la línea de comandos:
```
    firma.py [-h] [-v] -o ORIGEN [-d DESTINO] -c CERTIFICADO -p CLAVE
``` 

* O importandolo al proyecto:
```
from firma.py import firma_xml
...  
firma_xml(certificado, clave, factura_xml, factura_xml_firmada)
```
