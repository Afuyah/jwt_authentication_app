#!/usr/bin/env python3
import os
import sys

expected_structure = {
    'auth_system/': {
        'app/': {
            '__init__.py': None,
            'auth/': {
                '__init__.py': None,
                'models.py': None,
                'routes.py': None,
                'services.py': None,
                'utils.py': None,
                'forms.py': None,
                'api.py': None
            },
            'home/': {
                '__init__.py': None,
                'routes.py': None,
                'forms.py': None
            },
            'common/': {
                '__init__.py': None,
                'decorators.py': None,
                'utils.py': None,
                'validators.py': None
            },
            'templates/': {
                'auth/': {
                    'login.html': None,
                    'register.html': None,
                    'base.html': None
                },
                'home/': {
                    'base.html': None,
                    'index.html': None,
                    'dashboard.html': None
                }
            },
            'static/': {
                'css/': {
                    'auth.css': None
                }
            }
        },
        'migrations/': {
            '__init__.py': None,
            'versions/': {}
        },
        'tests/': {
            '__init__.py': None,
            'test_auth.py': None,
            'test_models.py': None
        },
        'config.py': None,
        'requirements.txt': None,
        'run.py': None,
        'create_admin.py': None,
        'README.md': None
    }
}

def check_structure(base_path, structure):
    for item, substructure in structure.items():
        item_path = os.path.join(base_path, item)
        
        if substructure is None:  # It's a file
            if not os.path.isfile(item_path):
                print(f"Missing file: {item_path}")
                return False
        else:  # It's a directory
            if not os.path.isdir(item_path):
                print(f"Missing directory: {item_path}")
                return False
            if not check_structure(item_path, substructure):
                return False
    
    return True

if check_structure('.', expected_structure):
    print("✅ All files and directories are in place!")
    sys.exit(0)
else:
    print("❌ Structure verification failed!")
    sys.exit(1)
