# Metadata Analyzer

A powerful CLI tool to **inspect, clean, and analyze image metadata** securely.  
Built with `exiftool-vendored`, it extracts EXIF data (camera, GPS, timestamps, etc.)  
and uses a smart heuristic engine to detect potential **hidden or malicious content** inside metadata.

---

##  Key Features

-  Extracts detailed metadata (camera model, date, ISO, focal length, dimensions, GPS, etc.)
-  Cleans and removes all embedded metadata safely
-  Generates Google Maps links when GPS coordinates are found
-  Detects malicious or suspicious data in metadata fields
-  Displays results in a formatted CLI table with risk levels:
  - 🟢 **Safe**
  - 🟠 **Caution**
  - 🔴 **Suspicious**
-  Creates individual JSON reports for each image inside `outputs/`
-  Saves cleaned images without metadata inside `cleaned_images/`
-  Works offline — no data is sent or uploaded anywhere

---

