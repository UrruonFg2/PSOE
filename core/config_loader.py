import configparser
import os
import json
from datetime import datetime, timedelta

class ConfigLoader:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config/config.ini')
        self.last_updated_path = 'db/last_updated.json'
        
    def get(self, section, option, fallback=None):
        return self.config.get(section, option, fallback=fallback)
    
    def getint(self, section, option, fallback=None):
        return self.config.getint(section, option, fallback=fallback)
    
    def getboolean(self, section, option, fallback=None):
        return self.config.getboolean(section, option, fallback=fallback)
    
    def should_update_databases(self):
        if not self.getboolean('VULN_DATABASES', 'auto_update', fallback=True):
            return False
            
        try:
            with open(self.last_updated_path, 'r') as f:
                last_update = json.load(f)
                last_date = datetime.strptime(last_update['date'], '%Y-%m-%d')
                frequency = self.getint('VULN_DATABASES', 'update_frequency', fallback=7)
                return (datetime.now() - last_date) > timedelta(days=frequency)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return True
    
    def record_update(self):
        with open(self.last_updated_path, 'w') as f:
            json.dump({'date': datetime.now().strftime('%Y-%m-%d')}, f)
    
    def load_profile(self, profile_name):
        profile_path = f"config/profiles/{profile_name}.ini"
        if not os.path.exists(profile_path):
            raise FileNotFoundError(f"Perfil de escaneo no encontrado: {profile_name}")
        
        profile = configparser.ConfigParser()
        profile.read(profile_path)
        return profile
