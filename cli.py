#!/usr/bin/python
# -*- coding: utf-8 -*- 

import fire

import l2tp


class SetupCli():

    def __init__(self):
        pass

    def setup(self, ipaddr, interface, psk=None, ip_range=None, username=None, passowrd=None):
        if not l2tp.is_root_user():
            exit(-1)
        
        psk = psk or l2tp.generate_password(16)
        ip_range = psk or '10.0.1'
        username = username or 'admin'
        passowrd = passowrd or l2tp.generate_password(16)

        setup_info = l2tp.SetupInfo()
        setup_info.ip_addr = ipaddr
        setup_info.interface_name = interface
        setup_info.vpn_ip_range = ip_range
        setup_info.vpn_psk = psk

        setup_info.print_parameters()

        l2tp.setup_dependences()
        l2tp.setup_config(setup_info)
        l2tp.setup_net_foward(setup_info)
        l2tp.setup_firewall_config(setup_info)
        l2tp.setup_autostart()
        l2tp.check_setup_result()

    def check(self):
        l2tp.check_setup_result()

    def add_user(self, username, password=None):
        password = password or l2tp.generate_password(16)

        print('Add new user:', username)
        print('Password:', password)

        l2tp.add_user(username, password)

    def del_user(self, username):
        l2tp.remove_user(username)

    def list_user(self):
        l2tp.list_users()
        

if __name__ == "__main__":
    fire.Fire(SetupCli)
