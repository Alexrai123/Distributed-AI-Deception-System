import unittest
from deception import FakeFilesystem, CommandSimulator

class TestDeception(unittest.TestCase):

    def setUp(self):
        self.fs = FakeFilesystem()
        self.sim = CommandSimulator(self.fs)

    def test_fs_navigation(self):
        self.assertEqual(self.fs.resolve_path('/root', '..'), '/')
        self.assertEqual(self.fs.resolve_path('/', 'etc'), '/etc')
        self.assertEqual(self.fs.resolve_path('/var/log', '../www'), '/var/www')

    def test_ls(self):
        output = self.sim.execute_command('ls /')
        self.assertIn('etc', output)
        self.assertIn('home', output)
        
        output = self.sim.execute_command('ls /nonexistent')
        self.assertIn('No such file', output)

    def test_cd(self):
        self.sim.execute_command('cd /etc')
        self.assertEqual(self.sim.current_path, '/etc')
        
        output = self.sim.execute_command('cd /nonexistent')
        self.assertIn('No such file', output)
        # Should stay in /etc
        self.assertEqual(self.sim.current_path, '/etc')

    def test_cat(self):
        output = self.sim.execute_command('cat /etc/passwd')
        self.assertIn('root:x:0:0', output)
        
        output = self.sim.execute_command('cat /etc/shadow')
        self.assertIn('root:*', output)

    def test_commands(self):
        self.assertEqual(self.sim.execute_command('whoami'), 'root')
        self.assertTrue('uid=0' in self.sim.execute_command('id'))
        self.assertEqual(self.sim.execute_command('pwd'), '/root')
        
    def test_unknown_command(self):
        self.assertIn('command not found', self.sim.execute_command('xyz123'))

    def test_deploy_decoy(self):
        self.fs.deploy_decoy('/home/secret.txt', 'Top Secret')
        output = self.sim.execute_command('cat /home/secret.txt')
        self.assertEqual(output, 'Top Secret')
        
        self.sim.execute_command('cd /home')
        ls_out = self.sim.execute_command('ls')
        self.assertIn('secret.txt', ls_out)

if __name__ == '__main__':
    unittest.main()
