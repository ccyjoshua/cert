# -*- coding: utf-8 -*-
from django.shortcuts import render, render_to_response
import ssl
from mainapp.utils.ssl_parser import SSLParser

# Create your views here.
def home_panel(request):
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        domain = keyword.split("//")[-1].split("/")[0]
        try:
            cert = ssl.get_server_certificate((domain, 443))
            response_data = SSLParser().get_cert_info_by_cert(cert)
            return render_to_response('home/result.html', response_data)
        except:
            return render(request, 'home/error.html')
    else:
        return render(request, 'home/panel.html')