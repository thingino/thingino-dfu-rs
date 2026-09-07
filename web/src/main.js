import '@fontsource/montserrat/400.css'
import '@fontsource/montserrat/500.css'
import '@fontsource/montserrat/600.css'
import '@fontsource/montserrat/700.css'
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap-icons/font/bootstrap-icons.css'
import * as bootstrap from 'bootstrap'
import './app.js'

document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(
  el => new bootstrap.Tooltip(el)
)
