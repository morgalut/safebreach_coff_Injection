# helpers.py

import os

def setup_custom_paths(launcher):
    """Setup custom paths from environment"""
    custom_loader_path = os.environ.get('CUSTOM_LOADER_PATH')
    if custom_loader_path:
        launcher.register_app_path('loader_enhanced.exe', custom_loader_path)
    
    custom_parser_path = os.environ.get('CUSTOM_PARSER_PATH') 
    if custom_parser_path:
        launcher.register_app_path('coff_parser_enhanced.exe', custom_parser_path)