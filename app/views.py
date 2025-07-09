import json
import os
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from fhirclient.models.patient import Patient
from fhirclient.models.bundle import Bundle
from fhirclient.models.observation import Observation

import secrets
import base64
import hashlib
import requests
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
# Configuration (you can put these in settings.py)
CLIENT_ID = os.getenv('CLIENT_ID')
SMART_AUTH_URL = os.getenv('SMART_AUTH_URL')
REDIRECT_URL = os.getenv('REDIRECT_URL')
FHIR_BASE_URL = os.getenv('FHIR_BASE_URL')
SMART_TOKEN_URL = os.getenv('SMART_TOKEN_URL')
CODE_VERIFIER_SESSION_KEY = 'code_verifier'

def generate_code_verifier(length=128):
    # Generate a random code verifier (RFC 7636)
    token = secrets.token_urlsafe(length)[:length]
    return token[:128]  # Maximum length is 128 characters

def generate_code_challenge(code_verifier):
    # Create the code challenge (SHA-256 hash of the verifier, base64 URL encoded)
    sha256_hash = hashlib.sha256(code_verifier.encode('ascii')).digest()
    # challenge = base64.urlsafe_b64encode(sha256).rstrip(b'=')
    code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii')[:-1]
    return code_challenge

def initiate_auth(request):
    # Generate PKCE challenge
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    token_string = None
    if os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY') in request.session:
        
        token_string = request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')]

    # Store the code verifier in the session
    request.session[CODE_VERIFIER_SESSION_KEY] = code_verifier
    
    # Build the authorization URL

    if token_string == None:
        params = {
            'client_id': CLIENT_ID,
            'scope': 'openid fhirUser',
            'redirect_uri': REDIRECT_URL,
            'response_type': 'code',
            # 'state': '1234567',
            # 'aud': FHIR_BASE_URL,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        auth_url = f"{SMART_AUTH_URL}?{urlencode(params)}"
        # print('auth_url : ' + auth_url)
        return redirect(auth_url)
    else:
        if 'issued_at' in request.session:
            issued_at = datetime.fromisoformat(request.session['issued_at'])
            now = datetime.now()
            
            diff = now - issued_at
            
            if diff.total_seconds() >= 3600:
                params = {
                    'client_id': CLIENT_ID,
                    'scope': 'openid fhirUser',
                    'redirect_uri': REDIRECT_URL,
                    'response_type': 'code',
                    # 'state': '1234567',
                    # 'aud': FHIR_BASE_URL,
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                }
                
                auth_url = f"{SMART_AUTH_URL}?{urlencode(params)}"
                
                return redirect(auth_url)
            else:            
                return redirect('app:patient-details')
        else:
            params = {
                'client_id': CLIENT_ID,
                'scope': 'openid fhirUser',
                'redirect_uri': REDIRECT_URL,
                'response_type': 'code',
                # 'state': '1234567',
                # 'aud': FHIR_BASE_URL,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
            }
            
            auth_url = f"{SMART_AUTH_URL}?{urlencode(params)}"
            
            return redirect(auth_url)
                        
def oauth_callback(request):
    code = request.GET.get('code')
    
    if not code:
        return HttpResponse("Authorization failed: no code returned", status=400)
    
    code_verifier = request.session.get(CODE_VERIFIER_SESSION_KEY)
    if not code_verifier:
        return HttpResponse("Session expired or invalid", status=400)
    
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URL,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier,
    }
    
    try:
        response = requests.post(SMART_TOKEN_URL, data=token_data)
        response.raise_for_status()
        token_response = response.json()
        
        if CODE_VERIFIER_SESSION_KEY in request.session:
            del request.session[CODE_VERIFIER_SESSION_KEY]

        request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')] = token_response
        request.session['issued_at'] = datetime.now().isoformat()
        
        # context = {
        #     'token_response': token_response
        # }
        # return render(request, 'app/patient-details.html', context)
        return redirect('app:patient-details')
        
    except requests.RequestException as e:
        return HttpResponse(f"Token request failed: {str(e)}", status=400)
    
def index(request):
    context = {}
    return render(request, 'app/index.html', context)

def get_epic_identifier(patient):
    if not hasattr(patient, 'identifier') or not patient.identifier:
        return None
    
    for identifier in patient.identifier:
        if (hasattr(identifier, 'type') and 
           (hasattr(identifier.type, 'text')) and 
           (identifier.type.text == 'EPIC')):
            return identifier.value
    
    return None
    
def patient_details(request):
    token_response = request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')]
    
    access_token = json.loads(json.dumps(token_response))['access_token']
    patient_id = json.loads(json.dumps(token_response))['patient']
    
    get_patient_url = os.getenv('FHIR_BASE_URL') + '/Patient/' + patient_id
    headers = {
        "Accept": "application/json",
        'Content-Type': 'application/json',
        "Authorization": "Bearer %s" % access_token
    }
    response = requests.get(get_patient_url, headers=headers)
    
    patient_json = response.json()
    fhir_patient = Patient(patient_json)
    
    epic_identifier = get_epic_identifier(fhir_patient)
    
    
    medications_list = medication_details(request)
    lab_results_list = lab_results(request)
    vital_signs_list = vital_signs(request)
    
    context = {
        'fhir_patient': fhir_patient,
        'epic_identifier': epic_identifier,
        'medications_list':medications_list,
        'lab_results_list':lab_results_list,
        'vital_signs_list':vital_signs_list
    }
    return render(request, 'app/patient-details.html', context) 
    
def extract_medications_from_fhir_bundle(bundle_obj: Bundle):
    medications = []

    for entry in bundle_obj.entry:
        resource = entry.resource
        if not resource:
            continue

        # Check resource type
        resource_type = resource.resource_type
        if resource_type in ["MedicationRequest", "MedicationStatement"]:
            med_info = {}

            # medicationCodeableConcept
            medication = getattr(resource, "medicationCodeableConcept", None)
            if medication and medication.coding:
                med_info["code"] = medication.coding[0].code
                med_info["display"] = medication.coding[0].display

            # medicationReference (optional)
            elif hasattr(resource, "medicationReference") and resource.medicationReference.display:
                med_info["display"] = resource.medicationReference.display

            # Dosage instructions
            if hasattr(resource, "dosageInstruction"):
                med_info["dosage"] = resource.dosageInstruction[0].text

            if hasattr(resource, "reasonCode"):
                med_info["reason"] = resource.reasonCode[0].text
                
            # Status, authoredOn
            med_info["status"] = getattr(resource, "status", None)
            med_info["authoredOn"] = getattr(resource, "authoredOn", None)

            medications.append(med_info)

    return medications  
    
def medication_details(request):
    token_response = request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')]
    
    access_token = json.loads(json.dumps(token_response))['access_token']
    patient_id = json.loads(json.dumps(token_response))['patient']
    
    get_medication_url = os.getenv('FHIR_BASE_URL') + '/MedicationRequest/' + patient_id
    get_medication_url = os.getenv('FHIR_BASE_URL') + '/MedicationRequest?subjet=' + patient_id
    
    headers = {
        "Accept": "application/json",
        'Content-Type': 'application/json',
        "Authorization": "Bearer %s" % access_token
    }
    response = requests.get(get_medication_url, headers=headers)
    
    patient_json = response.json()
    fhir_medication_bundle = Bundle(patient_json)
    
    medications_list = extract_medications_from_fhir_bundle(fhir_medication_bundle)
    context = {
        'medications_list': medications_list
    }
    return medications_list
    # return render(request, 'app/medication-details.html', context) 
  
def extract_laboratory_observations(bundle: Bundle):
    lab_observations = []

    for entry in bundle.entry:
        resource = entry.resource
        if resource.resource_type != "Observation":
            continue

        # Check if it has a "laboratory" category
        if resource.category:
            for category in resource.category:
                for coding in category.coding:
                    if coding.code == "laboratory":
                        # This is a lab observation — extract details
                        obs = {}

                        # Observation name
                        if resource.code and resource.code.coding:
                            obs["test_code"] = resource.code.coding[0].code
                            obs["test_name"] = resource.code.coding[0].display

                        # Value and unit
                        if resource.valueQuantity:
                            obs["value"] = resource.valueQuantity.value
                            obs["unit"] = resource.valueQuantity.unit

                        # Effective date/time
                        obs["effectiveDateTime"] = getattr(resource, "effectiveDateTime", None)

                        # Status
                        obs["status"] = getattr(resource, "status", None)

                        lab_observations.append(obs)
                        break  # Only one match needed, skip to next entry

    return lab_observations
  
def extract_vital_sings_observations(bundle: Bundle):
    lab_observations = []

    for entry in bundle.entry:
        resource = entry.resource
        if resource.resource_type != "Observation":
            continue

        # Check if it has a "laboratory" category
        if resource.category:
            for category in resource.category:
                for coding in category.coding:
                    if coding.code == "vital-signs":
                        # This is a lab observation — extract details
                        obs = {}

                        # Observation name
                        if resource.code and resource.code.coding:
                            obs["test_code"] = resource.code.coding[0].code
                            obs["test_name"] = resource.code.coding[0].display

                        # Value and unit
                        if resource.valueQuantity:
                            obs["value"] = resource.valueQuantity.value
                            obs["unit"] = resource.valueQuantity.unit

                        # Effective date/time
                        obs["effectiveDateTime"] = getattr(resource, "effectiveDateTime", None)

                        # Status
                        obs["status"] = getattr(resource, "status", None)

                        lab_observations.append(obs)
                        break  # Only one match needed, skip to next entry

    return lab_observations 
    
def lab_results(request):
    token_response = request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')]
    
    access_token = json.loads(json.dumps(token_response))['access_token']
    patient_id = json.loads(json.dumps(token_response))['patient']
    
    get_lab_results_url = os.getenv('FHIR_BASE_URL') + '/Observation?subjet=' + patient_id + '&category=laboratory'
    
    headers = {
        "Accept": "application/json",
        'Content-Type': 'application/json',
        "Authorization": "Bearer %s" % access_token
    }
    response = requests.get(get_lab_results_url, headers=headers)
    
    patient_json = response.json()
    fhir_observation_bundle = Bundle(patient_json)
    
    lab_results_list = extract_laboratory_observations(fhir_observation_bundle)
    context = {
        'lab_results_list': lab_results_list
    }
    
    return lab_results_list
    # return render(request, 'app/lab-results.html', context)     
    
def vital_signs(request):
    token_response = request.session[os.getenv('TOKEN_RESPONSE_LOCAL_STORAGE_KEY')]
    
    access_token = json.loads(json.dumps(token_response))['access_token']
    patient_id = json.loads(json.dumps(token_response))['patient']
    
    get_lab_results_url = os.getenv('FHIR_BASE_URL') + '/Observation?subjet=' + patient_id + '&category=vital-signs'
    
    headers = {
        "Accept": "application/json",
        'Content-Type': 'application/json',
        "Authorization": "Bearer %s" % access_token
    }
    response = requests.get(get_lab_results_url, headers=headers)
    print(response.text)
    patient_json = response.json()
    fhir_observation_bundle = Bundle(patient_json)
    
    vital_signs_list = extract_vital_sings_observations(fhir_observation_bundle)
    
    return vital_signs_list
    # context = {
    #     'vital_signs_list': vital_signs_list
    # }
    # return render(request, 'app/vital-signs.html', context) 
