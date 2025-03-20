from django.shortcuts import render

from django.views.generic import (
    CreateView,
    View
)
from django.views.generic.edit import (
    FormView
)
from .forms import (
    UserRegisterForm,
    LoginForm,
    UpdatePasswordForm,
    VerificationForm
)
from django.urls import reverse_lazy, reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.core.mail import send_mail
from .funtions import code_generator
from .sendgrid import send_mail_sendgrid


from .models import User

# Create your views here.

class UserRegisterView(FormView):
    template_name = 'users/register.html'
    form_class = UserRegisterForm
    success_url = '/'

    def form_valid(self, form):
        #generamos el codigo
        codigo = code_generator()
        #
        usuario = User.objects.create_user(
            form.cleaned_data['username'],
            form.cleaned_data['email'],
            form.cleaned_data['password1'],
            nombres=form.cleaned_data['nombres'],
            apellidos=form.cleaned_data['apellidos'],
            genero=form.cleaned_data['genero'],
            codregistro=codigo,
        )
        #enviar codigo al email del usuario
        asunto = 'Confirmacion de email'
        mensaje = 'Codigo de verificacion: ' + codigo
        email_remitente = 'bsliebano@gmail.com'
        #
        send_mail_sendgrid(email_remitente,form.cleaned_data['email'], asunto, codigo)
        #redirigir a pantalla de validacion

        return HttpResponseRedirect(
            reverse(
                'users_app:user-verification',
                kwargs={'pk':usuario.id}
            )
        )
    

class LoginUser(FormView):
    template_name= 'users/login.html'
    form_class=LoginForm
    success_url = reverse_lazy('home_app:panel')

    def form_valid(self, form):
        user = authenticate(
            username = form.cleaned_data['username'],
            password = form.cleaned_data['password'],
        )
        login(self.request, user)
        return super(LoginUser, self).form_valid(form)
    
class LogoutView(View):
    def get(self,request, *args, **kargs):
        logout(request)
        return HttpResponseRedirect(
            reverse(
                'users_app:user-login'
            )
        )

class UpdatePassword(LoginRequiredMixin, FormView):
    template_name= 'users/update.html'
    form_class = UpdatePasswordForm
    success_url = reverse_lazy('users_app:user-login')
    login_url = reverse_lazy('users_app:user-login')

    def form_valid(self, form):
        #encontrar el usuario activo
        usuario = self.request.user
        user = authenticate(
            username=usuario.username,
            password = form.cleaned_data['password1']
        )
        if user:
            new_password = form.cleaned_data['password2']
            usuario.set_password(new_password)
            usuario.save()

        logout(self.request)
        return super(UpdatePassword, self).form_valid(form)
    
class CodeVerificationView(FormView):
    template_name= 'users/verification.html'
    form_class=VerificationForm
    success_url = reverse_lazy('users_app:user-login')

    def get_form_kwargs(self):
        kwargs = super(CodeVerificationView, self).get_form_kwargs()
        kwargs.update({
            'pk': self.kwargs['pk']
        })
        return kwargs

    def form_valid(self, form):

        User.objects.filter(
            id=self.kwargs['pk']
        ).update(
            is_active=True
        )
        return super(CodeVerificationView, self).form_valid(form)