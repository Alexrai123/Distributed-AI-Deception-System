import json
import logging
import time
import os
import random
import string
from datetime import datetime

logger = logging.getLogger(__name__)

class FakeFilesystem:
    """
    Represents a virtual directory structure for the honeypot.
    """
    def __init__(self):
        self.fs = {
            '/': {'type': 'dir', 'contents': ['bin', 'etc', 'home', 'var', 'usr', 'tmp', 'root']},
            '/bin': {'type': 'dir', 'contents': ['ls', 'cd', 'pwd', 'cat', 'echo', 'bash', 'sh']},
            '/etc': {'type': 'dir', 'contents': ['passwd', 'shadow', 'hostname', 'hosts']},
            '/home': {'type': 'dir', 'contents': ['user']},
            '/home/user': {'type': 'dir', 'contents': []},
            '/var': {'type': 'dir', 'contents': ['log', 'www']},
            '/var/log': {'type': 'dir', 'contents': ['auth.log', 'syslog']},
            '/root': {'type': 'dir', 'contents': []},
            '/tmp': {'type': 'dir', 'contents': []},
            '/usr': {'type': 'dir', 'contents': ['bin', 'lib']},
        }
        
        # File contents
        self.file_contents = {
            '/etc/passwd': "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n",
            '/etc/shadow': "root:*:19777:0:99999:7:::\nuser:*:19777:0:99999:7:::\n",
            '/etc/hostname': "server01\n",
            '/etc/hosts': "127.0.0.1\tlocalhost\n127.0.1.1\tserver01\n"
        }
        
        self._load_decoy_blueprints()

    def _generate_random_string(self, length=16, use_chars=string.ascii_letters + string.digits):
        return ''.join(random.choice(use_chars) for _ in range(length))

    def _load_decoy_blueprints(self):
        """
        Loads decoy templates from JSON and populates the filesystem with highly realistic content.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        decoy_path = os.path.join(script_dir, "decoy_templates.json")
        
        if not os.path.exists(decoy_path):
            logger.warning(f"Decoy template file missing at {decoy_path}. Skipping dynamic population.")
            return

        try:
            with open(decoy_path, 'r') as f:
                data = json.load(f)
                
            templates = data.get("templates", [])
            
            # Persistent generated data for this honeypot session to ensure cross-file consistency
            session_data = {
                "INTERNAL_IP": f"10.0.{random.randint(1, 255)}.{random.randint(2, 254)}",
                "DB_HOST": f"db-prod-cluster.internal",
                "DB_NAME": "ecommerce_prod",
                "DB_USER": "prod_user",
                "DB_PASSWORD": self._generate_random_string(24),
                "DB_ROOT_USER": "root",
                "DB_ROOT_PASSWORD": self._generate_random_string(32),
                "REDIS_PASSWORD": self._generate_random_string(16),
                "APP_ENCRYPTION_KEY": self._generate_random_string(44),
                "PUBLIC_DOMAIN": "api.production-server.com",
                "ADMIN_EMAIL": "sysadmin@production-server.com",
                "MAILGUN_API_KEY": f"key-{self._generate_random_string(32)}",
                "RANDOM_AWS_ID_16": self._generate_random_string(16, string.ascii_uppercase + string.digits),
                "RANDOM_AWS_SECRET_40": self._generate_random_string(40),
                "RANDOM_AWS_ID_STAGING": self._generate_random_string(16, string.ascii_uppercase + string.digits),
                "RANDOM_AWS_SECRET_STAGING": self._generate_random_string(40),
                "ADMIN_NAME": "Alex H.",
                "BACKUP_SERVER": f"10.0.{random.randint(1,255)}.200",
                "BACKUP_SERVER_PASSWORD": self._generate_random_string(12),
                "JWT_SECRET": self._generate_random_string(64),
                "STAGING_PASSWORD": self._generate_random_string(10),
                "GITHUB_PAT_TOKEN": f"ghp_{self._generate_random_string(36)}",
                "ORG_NAME": "SecureCorpInc"
            }

            for tpl in templates:
                path = tpl.get("default_path")
                raw_content = tpl.get("content_template", "")
                
                # Dynamically resolve placeholders
                resolved_content = raw_content
                for key, val in session_data.items():
                    resolved_content = resolved_content.replace(f"{{{{{key}}}}}", val)
                    
                # Inject the generated decoy file directly into the filesystem
                self.deploy_decoy(path, resolved_content)
                
            logger.info(f"Successfully populated honeypot filesystem with {len(templates)} highly realistic AI decoy blueprints.")
            
        except Exception as e:
            logger.error(f"Failed to load decoy templates JSON: {e}")

    def resolve_path(self, current_path, new_path):
        """
        Resolves a path relative to current_path.
        """
        if new_path.startswith('/'):
            target = new_path
        else:
            if current_path == '/':
                target = '/' + new_path
            else:
                target = current_path + '/' + new_path
        
        # Normalize path (handle .. and .)
        parts = target.split('/')
        normalized = []
        for part in parts:
            if part == '' or part == '.':
                continue
            if part == '..':
                if normalized:
                    normalized.pop()
            else:
                normalized.append(part)
        
        return '/' + '/'.join(normalized)

    def list_dir(self, path):
        """
        Returns list of content names in a directory.
        Raises FileNotFoundError if path doesn't exist or isn't a dir.
        """
        if path not in self.fs:
             return None
        
        node = self.fs[path]
        if node['type'] != 'dir':
            return None # Not a directory
            
        return node['contents']

    def get_file_content(self, path):
        """
        Returns content of a file.
        """
        if path in self.file_contents:
            return self.file_contents[path]
        return None
        
    def is_dir(self, path):
         return path in self.fs and self.fs[path]['type'] == 'dir'

    def is_file(self, path):
        # Allow checking via file_contents keys or fs entries if validation needed
        return path in self.file_contents

    def deploy_decoy(self, path, content):
        """
        Deploy a decoy file. Handles recursive directory creation dynamically.
        """
        self.file_contents[path] = content
        
        parts = path.strip('/').split('/')
        filename = parts[-1]
        
        # Build path recursively
        current_dir = '/'
        for part in parts[:-1]:
            if not part: continue
            
            next_dir = f"{current_dir}{part}" if current_dir == '/' else f"{current_dir}/{part}"
            
            # Create if it doesn't exist
            if next_dir not in self.fs:
                self.fs[next_dir] = {'type': 'dir', 'contents': []}
                # Add it to parent's contents
                if part not in self.fs[current_dir]['contents']:
                    self.fs[current_dir]['contents'].append(part)
            
            current_dir = next_dir
            
        # Add the final file to the parent directory
        if current_dir in self.fs:
            if filename not in self.fs[current_dir]['contents']:
                self.fs[current_dir]['contents'].append(filename)


class CommandSimulator:
    """
    Simulates shell command execution using the FakeFilesystem.
    """
    def __init__(self, filesystem=None):
        self.fs = filesystem if filesystem else FakeFilesystem()
        self.current_path = '/root'
        self.hostname = 'server01'
        self.user = 'root'

    def execute_command(self, cmd_line):
        """
        Parses and executes a command line.
        Returns: output string
        """
        parts = cmd_line.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0]
        args = parts[1:]
        
        if cmd == 'ls':
            return self._cmd_ls(args)
        elif cmd == 'cd':
            return self._cmd_cd(args)
        elif cmd == 'pwd':
            return self.current_path
        elif cmd == 'cat':
            return self._cmd_cat(args)
        elif cmd == 'whoami':
            return self.user
        elif cmd == 'id':
            return f"uid=0({self.user}) gid=0({self.user}) groups=0({self.user})"
        elif cmd == 'uname':
            if '-a' in args:
                return "Linux server01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
            return "Linux"
        elif cmd == 'exit':
            return "EXIT"
        elif cmd in ['wget', 'curl', 'apt', 'apt-get', 'yum']:
             return f"{cmd}: command not found" # Or fake a download
        else:
            return f"{cmd}: command not found"

    def _cmd_ls(self, args):
        target = self.current_path
        
        # Filter out flags like -la, -l, -a
        paths = [arg for arg in args if not arg.startswith('-')]
        
        if paths:
            target = self.fs.resolve_path(self.current_path, paths[0])
            
        contents = self.fs.list_dir(target)
        if contents is None:
            if self.fs.is_file(target):
                return paths[0] if paths else target
            return f"ls: cannot access '{paths[0] if paths else target}': No such file or directory"
            
        return "  ".join(contents)

    def _cmd_cd(self, args):
        if not args:
            self.current_path = '/root' # Default to home
            return ""
            
        target = self.fs.resolve_path(self.current_path, args[0])
        if self.fs.is_dir(target):
            self.current_path = target
            return ""
        else:
            return f"cd: {args[0]}: No such file or directory"

    def _cmd_cat(self, args):
        if not args:
            return ""
            
        target = self.fs.resolve_path(self.current_path, args[0])
        content = self.fs.get_file_content(target)
        
        if content is not None:
            return content
        elif self.fs.is_dir(target):
            return f"cat: {args[0]}: Is a directory"
        else:
            return f"cat: {args[0]}: No such file or directory"
