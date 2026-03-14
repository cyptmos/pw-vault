import pytest
import os
from pathlib import Path
from unittest.mock import patch
from src.main import VaultContext  # Assuming your script is main.py

@pytest.fixture
def temp_vault(tmp_path):
    """Fixture to provide a temporary path for a vault file."""
    return tmp_path / "test_vault.pw"

def test_vault_initialization(temp_vault):
    """Test that a new vault can be created and saved."""
    vm = VaultContext(temp_vault)
    
    # We mock getpass so it 'types' the password for us automatically
    with patch('getpass.getpass', side_effect=['password123', 'password123']):
        vm.load_file()
    
    assert temp_vault.exists()
    assert vm.data['version'] == 0.1
    assert vm.data['accounts'] == {}

def test_vault_save_and_load(temp_vault):
    """Test that data written to the vault survives a reload."""
    # 1. Create and save data
    vm = VaultContext(temp_vault)
    with patch('getpass.getpass', side_effect=['secret', 'secret']):
        vm.load_file()
    
    vm.data['accounts']['github'] = {"password": "git_password"}
    vm.save()

    # 2. Re-instantiate and load
    vm2 = VaultContext(temp_vault)
    with patch('getpass.getpass', return_value='secret'):
        vm2.load_file()
    
    assert vm2.data['accounts']['github']['password'] == "git_password"

def test_invalid_password(temp_vault):
    """Test that an incorrect password triggers a SystemExit."""
    vm = VaultContext(temp_vault)
    # Create the vault first
    with patch('getpass.getpass', side_effect=['real_pass', 'real_pass']):
        vm.load_file()
    
    # Try to load with wrong pass
    vm2 = VaultContext(temp_vault)
    with patch('getpass.getpass', return_value='wrong_pass'):
        with pytest.raises(SystemExit): # We expect the app to exit
            vm2.load_file()