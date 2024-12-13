import base64
import os
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login as lg, logout
from django.contrib.auth import authenticate
from django.contrib import messages
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from django.contrib.auth.models import User

from .forms import Registro
def index(request):
    if request.method == 'POST':
        text_plain = request.POST.get('userInfo')
        if text_plain:
            llave = sha_256(text_plain)
            aes = cifradoAES(bytes.fromhex(llave), text_plain)
            encrypted_base64 = base64.b64encode(aes[0]).decode('utf-8')

            descifrar = descifradoAES(bytes.fromhex(llave), aes[0], aes[1], aes[2])
            locator= sha_256(encrypted_base64)
            messages.success(request,  llave+'')
            messages.success(request,encrypted_base64+'')
            messages.success(request, descifrar)
            messages.success(request, locator)
    
    return render(request, 'index.html', {})

def sha_256(text_plain):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(text_plain.encode('utf-8'))
    return digest.finalize().hex()

def cifradoAES(llave, text_plain):
    nonce = os.urandom(12)  # AES-GCM requiere un nonce de 12 bytes
    
    # Crear el cifrador AES en modo GCM
    cipher = Cipher(algorithms.AES(llave), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encriptar el texto plano
    ciphertext = encryptor.update(text_plain.encode('utf-8')) + encryptor.finalize()
    
    return (ciphertext, nonce, encryptor.tag)


def descifradoAES(llave, ciphertext, nonce, tag):
    # Crear el cifrador AES en modo GCM
    cipher = Cipher(algorithms.AES(llave), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Desencriptar el texto cifrado
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_text.decode('utf-8')

def login(request):

    if request.method == 'POST':
        username =request.POST.get('username')
        password =request.POST.get('password')

        usuarios = authenticate(username=username,password=password)
        if usuarios:
            lg(request,usuarios)
            return redirect('index')
        else:
            messages.error(request,'Usuario o contraseña incorrecta')
            return redirect('login')
        
    return render(request,'users/login.html',{})
        
def cerrarsesion(request):
    logout(request)
    messages.success(request,'Has cerrado sesion correctamente')        
    return redirect('login')

def registro(request):
    form = Registro(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        usuario = form.save()
        if usuario:
            lg(request,usuario)
            messages.success(request,'Usuario registrado correctamente')
            return redirect('index')
        
    return render(request,'users/registro.html',{
        'form':form
        
    })
