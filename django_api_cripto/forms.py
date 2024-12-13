from django import forms 
from django.contrib.auth.models import User

class Registro(forms.Form):
    username = forms.CharField(label='Nombre de usuario', min_length=3,max_length=100, widget=forms.TextInput(attrs={'class':'form-control'})) 
    email = forms.EmailField(label='Correo electronico', max_length=100, widget=forms.EmailInput(attrs={'class':'form-control'}))
    password = forms.CharField(label='Contraseña', min_length=5,max_length=100, widget=forms.PasswordInput(attrs={'class':'form-control'}))
    password2 = forms.CharField(label='Repetir contraseña',min_length=5, max_length=100, widget=forms.PasswordInput(attrs={'class':'form-control'}))
 


    def clean_username(self):
        username = self.cleaned_data['username']
        username_taken = User.objects.filter(username=username).exists()
        if username_taken:
            raise forms.ValidationError('El nombre de usuario ya está en uso.')
        return username
    
    def clean_email(self):
        email = self.cleaned_data['email']
        email_taken = User.objects.filter(email=email).exists()
        if email_taken:
            raise forms.ValidationError('El correo electronico ya está en uso.')
        return email
    
    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password2') != cleaned_data.get('password'):
            self.add_error('password2', 'Las contraseñas no coinciden')
        return cleaned_data
    
    def save(self):
        return User.objects.create_user(
            self.cleaned_data.get('username'),
            self.cleaned_data.get('email'),
            self.cleaned_data.get('password')
        )