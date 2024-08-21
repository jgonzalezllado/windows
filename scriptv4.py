import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox
import subprocess

def ejecutar_comando_powershell(comando):
    try:
        resultado = subprocess.run(["powershell", "-Command", comando], capture_output=True, text=True, shell=True)
        return resultado
    except Exception as e:
        return None, str(e)

def obtener_usuario_actual():
    try:
        resultado = subprocess.run("powershell -Command \"[System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\\')[-1]\"", capture_output=True, text=True, shell=True)
        return resultado.stdout.strip()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo obtener el nombre del usuario actual:\n{str(e)}")
        return None

def desactivar_telemetria():
    comando_crear_clave = (
        'if (-not (Test-Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection")) {'
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows" -Name "DataCollection" -Force'
        '}'
    )
    resultado_crear_clave = ejecutar_comando_powershell(comando_crear_clave)
    
    if resultado_crear_clave and resultado_crear_clave.returncode != 0:
        messagebox.showerror("Error", f"No se pudo crear la clave de registro para la telemetría:\n{resultado_crear_clave.stderr}")
        return

    comando_desactivar_telemetria = (
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name "AllowTelemetry" -Value 0 -Force'
    )
    resultado_desactivar = ejecutar_comando_powershell(comando_desactivar_telemetria)

    if resultado_desactivar and resultado_desactivar.returncode == 0:
        messagebox.showinfo("Éxito", "La telemetría ha sido desactivada con éxito.")
    else:
        messagebox.showerror("Error", f"Hubo un problema al desactivar la telemetría:\n{resultado_desactivar.stderr}")

def deshabilitar_cambio_fondo():
    comando_crear_clave = (
        'if (-not (Test-Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop")) {'
        'New-Item -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies" -Name "ActiveDesktop" -Force'
        '}'
    )
    comando_deshabilitar_fondo = (
        'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" -Name "NoChangingWallPaper" -Value 1 -Force'
    )
    
    resultado_crear_clave = ejecutar_comando_powershell(comando_crear_clave)
    
    if resultado_crear_clave and resultado_crear_clave.returncode != 0:
        messagebox.showerror("Error", f"No se pudo crear la clave de registro para el cambio de fondo:\n{resultado_crear_clave.stderr}")
        return

    resultado_deshabilitar = ejecutar_comando_powershell(comando_deshabilitar_fondo)

    if resultado_deshabilitar and resultado_deshabilitar.returncode == 0:
        messagebox.showinfo("Éxito", "El cambio de fondo de pantalla ha sido deshabilitado.")
    else:
        messagebox.showerror("Error", f"Hubo un problema al deshabilitar el cambio de fondo de pantalla:\n{resultado_deshabilitar.stderr}")

def habilitar_cambio_fondo():
    comando_crear_clave = (
        'if (-not (Test-Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop")) {'
        'New-Item -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies" -Name "ActiveDesktop" -Force'
        '}'
    )
    comando_habilitar_fondo = (
        'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" -Name "NoChangingWallPaper" -Value 0 -Force'
    )
    
    resultado_crear_clave = ejecutar_comando_powershell(comando_crear_clave)
    
    if resultado_crear_clave and resultado_crear_clave.returncode != 0:
        messagebox.showerror("Error", f"No se pudo crear la clave de registro para el cambio de fondo:\n{resultado_crear_clave.stderr}")
        return

    resultado_habilitar = ejecutar_comando_powershell(comando_habilitar_fondo)

    if resultado_habilitar and resultado_habilitar.returncode == 0:
        messagebox.showinfo("Éxito", "El cambio de fondo de pantalla ha sido habilitado.")
    else:
        messagebox.showerror("Error", f"Hubo un problema al habilitar el cambio de fondo de pantalla:\n{resultado_habilitar.stderr}")

def unir_a_dominio():
    dominio = simpledialog.askstring("Unir a Dominio", "Ingrese el nombre del dominio:")
    if not dominio:
        messagebox.showwarning("Advertencia", "El nombre del dominio no puede estar vacío.")
        return
    
    usuario = simpledialog.askstring("Unir a Dominio", "Ingrese el nombre de usuario con permisos:", show='*')
    if not usuario:
        messagebox.showwarning("Advertencia", "El nombre de usuario no puede estar vacío.")
        return
    
    contrasena = simpledialog.askstring("Unir a Dominio", "Ingrese la contraseña:", show='*')
    if not contrasena:
        messagebox.showwarning("Advertencia", "La contraseña no puede estar vacía.")
        return
    
    comando = (
        f"$securePass = ConvertTo-SecureString '{contrasena}' -AsPlainText -Force; "
        f"$cred = New-Object System.Management.Automation.PSCredential('{usuario}', $securePass); "
        f"Add-Computer -DomainName '{dominio}' -Credential $cred -Force -Restart"
    )
    
    resultado = ejecutar_comando_powershell(comando)
    
    if resultado and resultado.returncode == 0:
        messagebox.showinfo("Éxito", "El equipo se ha unido al dominio y se reiniciará para aplicar los cambios.")
    else:
        messagebox.showerror("Error", f"Hubo un problema al intentar unir el equipo al dominio:\n{resultado.stderr}")

def cambiar_nombre_usuario():
    nuevo_nombre = entry_nombre.get().strip()
    if not nuevo_nombre:
        messagebox.showwarning("Advertencia", "El nuevo nombre de usuario no puede estar vacío.")
        return
    
    usuario_actual = obtener_usuario_actual()
    if not usuario_actual:
        return
    
    comando = f'Rename-LocalUser -Name "{usuario_actual}" -NewName "{nuevo_nombre}"'
    resultado = ejecutar_comando_powershell(comando)

    if resultado and resultado.returncode == 0:
        messagebox.showinfo("Éxito", "El nombre de usuario ha sido cambiado con éxito.")
        entry_nombre.delete(0, tk.END)
    else:
        messagebox.showerror("Error", f"Hubo un problema al cambiar el nombre de usuario:\n{resultado.stderr}")

def cambiar_contrasena():
    nueva_contrasena = entry_contrasena.get().strip()
    if not nueva_contrasena:
        messagebox.showwarning("Advertencia", "La nueva contraseña no puede estar vacía.")
        return
    
    usuario_actual = obtener_usuario_actual()
    if not usuario_actual:
        return
    
    comando = f'Set-LocalUser -Name "{usuario_actual}" -Password (ConvertTo-SecureString "{nueva_contrasena}" -AsPlainText -Force)'
    resultado = ejecutar_comando_powershell(comando)

    if resultado and resultado.returncode == 0:
        messagebox.showinfo("Éxito", "La contraseña ha sido cambiada con éxito.")
        entry_contrasena.delete(0, tk.END)
    else:
        messagebox.showerror("Error", f"Hubo un problema al cambiar la contraseña:\n{resultado.stderr}")

def mejorar_rendimiento():
    comando = (
        'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Performance" -Name "VisualEffects" -Value 2 -Force; '
        'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Performance" -Name "AdjustForPerformance" -Value 1 -Force'
    )
    resultado = ejecutar_comando_powershell(comando)
    
    if resultado and resultado.returncode == 0:
        messagebox.showinfo("Éxito", "El rendimiento ha sido optimizado.")
    else:
        messagebox.showerror("Error", f"Hubo un problema al optimizar el rendimiento:\n{resultado.stderr}")

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Script Julia")

# Configurar el grid layout con un padding general
ventana.grid_columnconfigure(0, weight=1)
ventana.grid_columnconfigure(1, weight=1)
ventana.grid_columnconfigure(2, weight=1)

# Crear y colocar los widgets
etiqueta_info = tk.Label(ventana, text="Seleccione la acción que desea realizar:")
etiqueta_info.grid(row=0, column=0, columnspan=3, pady=10)

boton_desactivar = tk.Button(ventana, text="Desactivar Telemetría", command=desactivar_telemetria)
boton_desactivar.grid(row=1, column=0, columnspan=3, pady=5, sticky="ew")

boton_deshabilitar_fondo = tk.Button(ventana, text="Deshabilitar Cambio de Fondo", command=deshabilitar_cambio_fondo)
boton_deshabilitar_fondo.grid(row=2, column=0, columnspan=3, pady=5, sticky="ew")

boton_habilitar_fondo = tk.Button(ventana, text="Habilitar Cambio de Fondo", command=habilitar_cambio_fondo)
boton_habilitar_fondo.grid(row=3, column=0, columnspan=3, pady=5, sticky="ew")

boton_unir_dominio = tk.Button(ventana, text="Unir a Dominio", command=unir_a_dominio)
boton_unir_dominio.grid(row=4, column=0, columnspan=3, pady=5, sticky="ew")

boton_mejorar_rendimiento = tk.Button(ventana, text="Mejorar Rendimiento", command=mejorar_rendimiento)
boton_mejorar_rendimiento.grid(row=7, column=0, columnspan=3, pady=5, sticky="ew")

# Cambiar nombre de usuario
etiqueta_nombre = tk.Label(ventana, text="Nuevo Nombre de Usuario:")
etiqueta_nombre.grid(row=5, column=0, padx=5, pady=10, sticky='e')
entry_nombre = tk.Entry(ventana)
entry_nombre.grid(row=5, column=1, padx=5, pady=10, sticky='w')
boton_cambiar_nombre = tk.Button(ventana, text="OK", command=cambiar_nombre_usuario)
boton_cambiar_nombre.grid(row=5, column=2, padx=5, pady=10)

# Cambiar contraseña
etiqueta_contrasena = tk.Label(ventana, text="Nueva Contraseña:")
etiqueta_contrasena.grid(row=6, column=0, padx=5, pady=10, sticky='e')
entry_contrasena = tk.Entry(ventana, show='*')
entry_contrasena.grid(row=6, column=1, padx=5, pady=10, sticky='w')
boton_cambiar_contrasena = tk.Button(ventana, text="OK", command=cambiar_contrasena)
boton_cambiar_contrasena.grid(row=6, column=2, padx=5, pady=10)

# Iniciar la aplicación
ventana.mainloop()
