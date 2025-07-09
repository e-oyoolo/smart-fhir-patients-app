from django.urls import path, include
from . import views

app_name = 'app'

urlpatterns = [
    path('', views.index, name="index"),
    path('auth/', views.initiate_auth, name='initiate_auth'),
    path('api/callback/', views.oauth_callback, name='api/callback/'),
    path('patient-details/', views.patient_details, name='patient-details'),
    path('medication-details/', views.medication_details, name='medication-details'),
    path('lab-results/', views.lab_results, name='lab-results'),
    path('vital-signs/', views.vital_signs, name='vital-signs'),
]
