#!/usr/bin/env python

from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.vars import VariableManager
from ansible.inventory import Inventory
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager


class AnsibleCore(object):
    def __init__(self):
        # initialize needed objects
        self.variable_manager = VariableManager()
        self.loader = DataLoader()
        self.passwords = dict(vault_pass='secret')

    def run_scan(self, auth, host_list, scan_type='rhel'):
        if auth.type == "ssh_key":
            my_options = namedtuple('Options', ['connection', 'module_path', 'forks', 'become', 'become_method',
                                                'become_user', 'check', 'remote_user'])
            options = my_options(connection='ssh', module_path='/home/mvickstr/PyCharmProjects/rho_2_0/src/',
                                 forks=100, become=None, become_method=None, become_user=None, check=False,
                                 remote_user=auth.username)
            self.variable_manager.extra_vars = {'ansible_ssh_private_key_file': auth.key}
        elif auth.type == "ssh":
            my_options = namedtuple('Options', ['connection', 'module_path', 'forks', 'become', 'become_method',
                                                'become_user', 'check', 'remote_user'])
            options = my_options(connection='ssh', module_path='/home/mvickstr/PyCharmProjects/rho_2_0/src/',
                                 forks=100, become=None, become_method=None, become_user=None, check=False,
                                 remote_user=auth.username)
            self.variable_manager.extra_vars = {'ansible_ssh_pass': auth.password}
        else:
            # auth type not recognized
            return False

        # create inventory and pass to var manager
        inventory = Inventory(loader=self.loader, variable_manager=self.variable_manager,
                              host_list=host_list)

        if scan_type == 'rhel':
            # create play with tasks
            play_source = dict(
                name="Scan RHEL",
                hosts=host_list,
                gather_facts='no',
                tasks=[dict(action=dict(module='scan_rhel2', args=''), register='')]
            )
        elif scan_type == 'jboss':
            # create play with tasks
            play_source = dict(
                name="Scan JBoss",
                hosts=host_list,
                gather_facts='no',
                tasks=[dict(action=dict(module='shell', args='ls'), register='shell_out'),
                       dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}')))
                       ]
            )
        else:
            print "scan_type not recognized"
            return False
        play = Play().load(play_source, variable_manager=self.variable_manager, loader=self.loader)

        # actually run it
        tqm = None
        try:
            tqm = TaskQueueManager(
                inventory=inventory,
                variable_manager=self.variable_manager,
                loader=self.loader,
                options=options,
                passwords=self.passwords,
                stdout_callback='default',
            )
            result = tqm.run(play)
        finally:
            if tqm is not None:
                tqm.cleanup()
