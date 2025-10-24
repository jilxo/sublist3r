# Sublist3r

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-2.7%20%7C%203.x-blue.svg)
![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)

Sublist3r es una herramienta de enumeración de subdominios diseñada para penetration testers y profesionales de seguridad. Utiliza múltiples motores de búsqueda y fuentes públicas para descubrir subdominios de un dominio objetivo.

## 🚀 Características

- **Múltiples fuentes**: Consulta varios motores de búsqueda para encontrar subdominios
- **Bruteforce integrado**: Módulo de fuerza bruta utilizando subbrute
- **Escaneo de puertos**: Capacidad de escanear puertos TCP en los subdominios encontrados
- **Multi-threading**: Soporte para múltiples hilos para acelerar el proceso
- **Rotación de User-Agent**: Evita detección mediante rotación automática de User-Agents
- **Exportación de resultados**: Guarda los resultados en archivos de texto
- **Compatible**: Funciona con Python 2.7 y Python 3.x

## 📋 Requisitos

- Python 2.7 o Python 3.x
- pip (gestor de paquetes de Python)

## 🔧 Instalación

### Clonar el repositorio

```bash path=null start=null
git clone https://github.com/tuusuario/sublist3r.git
cd sublist3r
```

### Instalar dependencias

```bash path=null start=null
pip install -r requirements.txt
```

O instalar el paquete completo:

```bash path=null start=null
python setup.py install
```

## 💻 Uso

### Uso básico

```bash path=null start=null
python sublist3r.py -d example.com
```

### Opciones avanzadas

```bash path=null start=null
# Enumeración con bruteforce
python sublist3r.py -d example.com -b

# Especificar número de hilos para bruteforce
python sublist3r.py -d example.com -b -t 50

# Escanear puertos en subdominios encontrados
python sublist3r.py -d example.com -p 80,443,8080

# Guardar resultados en archivo
python sublist3r.py -d example.com -o resultados.txt

# Modo verbose para ver resultados en tiempo real
python sublist3r.py -d example.com -v

# Especificar motores de búsqueda específicos
python sublist3r.py -d example.com -e google,bing,yahoo

# Sin colores en la salida
python sublist3r.py -d example.com -n
```

### Parámetros

| Opción | Descripción |
|--------|-------------|
| `-d`, `--domain` | Dominio a enumerar (requerido) |
| `-b`, `--bruteforce` | Habilitar módulo de bruteforce |
| `-p`, `--ports` | Escanear puertos TCP especificados |
| `-v`, `--verbose` | Mostrar resultados en tiempo real |
| `-t`, `--threads` | Número de hilos para bruteforce (default: 30) |
| `-e`, `--engines` | Motores de búsqueda específicos (separados por comas) |
| `-o`, `--output` | Guardar resultados en archivo |
| `-n`, `--no-color` | Salida sin colores |

## 🔍 Ejemplo de salida

```bash path=null start=null
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela - @aboul3la

[-] Enumerating subdomains now for example.com
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Yahoo..
[-] Total Unique Subdomains Found: 15
www.example.com
mail.example.com
blog.example.com
...
```

## 🛡️ Características de seguridad

- **Anti-detección**: Rotación automática de User-Agents para evitar bloqueos
- **Rate limiting**: Control de velocidad de peticiones
- **Backoff exponencial**: Reintentos inteligentes cuando se detecta rate limiting
- **Headers realistas**: Utiliza headers de navegadores modernos

## 🤝 Contribución

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está licenciado bajo GPL-2.0 - ver el archivo LICENSE para más detalles.

## ⚠️ Disclaimer

Esta herramienta es solo para fines educativos y de pruebas de seguridad autorizadas. El uso de Sublist3r para atacar objetivos sin consentimiento previo es ilegal. Es responsabilidad del usuario final cumplir con todas las leyes locales, estatales y federales aplicables. Los desarrolladores no asumen ninguna responsabilidad y no son responsables de ningún mal uso o daño causado por este programa.

## 👤 Autor

- **Ahmed Aboul-Ela** - [@aboul3la](https://twitter.com/aboul3la)

## 🔗 Enlaces útiles

- [Reporte de bugs](https://github.com/tuusuario/sublist3r/issues)
- [Solicitar funcionalidad](https://github.com/tuusuario/sublist3r/issues)

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub
