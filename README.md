# Sublist3r
> [!NOTE]
> Esto solo es una modificacion del codigo original de este repo (https://github.com/aboul3la/Sublist3r)
> Donde se añadió un método para DNS Dumpster que nos permite utilizar la api en vez del scrapping

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-2.7%20%7C%203.x-blue.svg)
![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)


## 📋 Requisitos

- Python 2.7 o Python 3.x
- pip (gestor de paquetes de Python)
- Es necesario tener una API Key de DNS Dumpster 

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

```
bash path=null start=null
python setup.py install
```

### Configurar la API Key en el entorno
```
export DNSDUMPSTER_KEY=tu_api_key
```
o
```
echo "tu_api_key" > ~/.dnsdumpster_api_key
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

## ⚠️ Disclaimer

Esta herramienta es solo para fines educativos y de pruebas de seguridad autorizadas. El uso de Sublist3r para atacar objetivos sin consentimiento previo es ilegal. Es responsabilidad del usuario final cumplir con todas las leyes locales, estatales y federales aplicables. Los desarrolladores no asumen ninguna responsabilidad y no son responsables de ningún mal uso o daño causado por este programa.

## 👤 Autor

- **Ahmed Aboul-Ela** - [@aboul3la](https://twitter.com/aboul3la)

## 🔗 Enlaces útiles

- [Reporte de bugs](https://github.com/tuusuario/sublist3r/issues)
- [Solicitar funcionalidad](https://github.com/tuusuario/sublist3r/issues)

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub
