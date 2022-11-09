#!/usr/bin/python
# Copyright (c) 2022 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,  this list of conditions and the following disclaimer in the documentation 
#   and/or other materials provided with the distribution.
# * Neither the name of the Arista nor the names of its contributors may be used to endorse or promote products derived from this software without 
#   specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

import logging, time, sys, argparse
from cvprac.cvp_client import CvpClient
import urllib3
urllib3.disable_warnings()
import json
from copy import deepcopy
import ipaddress
import yaml
from getpass import getpass

TEST_MODE = True
EXPORT_CVP_DATA = True
GENERATE_GENERIC = True


class ipGenerator():
   '''
   ipGenerator - act as a provider of IP addresses
   The pool is created and then the # of reserved IPs is deleted from the pool

      Parameters;
         subnet (str): The IP Subnet that we have been allocated
         num_reserved (int): The number of IPs from the start of the pool that we should assume in use

      Methods:
         get(): Get an un-allocated IP
         put(str): Put an IP back in the pool
   
   '''
   def __init__(self,subnet="192.168.0.0/24",num_reserved=5):
      self.ip_block = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
      self.ip_block.reverse()

      for x in range(num_reserved+1):
         self.ip_block.pop()

   def get(self):
      return self.ip_block.pop()
   
   def put(self, ip):
      self.ip_block.append(ip)



def build_node_list(inventory, mgmt_ip, log, streaming_active=False):
   '''
   build_node_list - Build a list of EOS nodes, based on the inputs

      Parameters;
         inventory (list): CVP inventory output - a list of dicts containing the standard CVP inventory
         mgmt_ip (ipGenerator): An instance of the ipGenerator class to provide the updated management IPs
         log (logging): Instance of the logger
         streaming_active (bool): Filter out any nodes that aren't actively streaming. Non CVP nodes will still be 
            generated as generic types if the topology requires it

      Returns:
         A list of nodes, a dict of structure {serial:hostname}, and a list of EOS nodes not currently streaming
   '''
   nodeList = []
   serialTable = {}
   blacklist = []
   
   node = {}
   for entry in inventory:
      log.debug('Processing %s', entry['hostname'])
      node[ entry['hostname'] ] = {}
      node[ entry['hostname'] ]['ip_addr'] = mgmt_ip.get()
      node[ entry['hostname'] ]['node_type'] = 'veos'
      node[ entry['hostname'] ]['version'] = entry['version']
      node[ entry['hostname'] ]['neighbors'] = []

      log.debug('Ready to create: %s', entry['hostname'])
      if streaming_active is True:
         if entry['streamingStatus'] != 'active':
            log.warning('Not creating %s as is not currently streaming', entry['hostname'])
            mgmt_ip.put(node[ entry['hostname'] ]['ip_addr'])
            blacklist.append(entry['hostname'])
         else:
            log.debug('Creating node: %s', entry['hostname'])
            nodeList.append(deepcopy(node))
      else:
         nodeList.append(deepcopy(node))
      node.clear()

      serialTable[ entry['serialNumber'] ] = entry['hostname']

   return nodeList,serialTable,blacklist


def generate_edges(raw_topology, serials, mgmt_ip, log, blacklist=[]):
   '''
   generate_edges - generate a list of the links in the topology

      Parameters;
         raw_topology (dict): the cvp API call response with the topology
         serials (dict): the generated lookup table of serials : hostnames
         mgmt_ip (ipGenerator): the instance of the ipGenerator for the management pool
         log(logging): logging instance
         blackkist(list(str)): list of nodes that are in the CVP inventory, but whose presence we don't need to infer
      
      Returns:
         edgeSet(list): A list of neighbors with the link information
         extra_nodes(list): A list of generic nodes that are inferred from the link information
   
   '''
   edgeSet = {}
   extra_nodes = []
   node = {}
   _temp_edges = []

   for notification in raw_topology['notifications']:
      for entry in notification['updates']:
         sideA = notification['updates'][entry]['key']['from']
         sideB = notification['updates'][entry]['key']['to']
         
         for sideA_interface in notification['updates'][entry]['value'].keys():
            for element in notification['updates'][entry]['value'][sideA_interface]:
               sideB_interface = notification['updates'][entry]['value'][sideA_interface][element]['key']['neighborPort']
               # ATC takes a node centric view so the edges need to be configured on both nodes
               _temp_edges.append( (sideA, sideA_interface, sideB, sideB_interface) )
               # We handle this by creating the edges in pairs
               _temp_edges.append( (sideB, sideB_interface, sideA, sideA_interface) )


   log.debug("%d edges mapped", len(_temp_edges)/2)

   for entry in _temp_edges:
      
      if 'Vxlan1' not in entry:

         local_hostname = entry[0]
         if entry[0] in serials:
            local_hostname = serials[entry[0]]
         elif any(local_hostname in x for x in extra_nodes):
            pass
         else:
            if local_hostname not in blacklist:
               log.debug('Creating generic node for %s' % entry[0])
               node[local_hostname] = {}
               node[local_hostname]['ip_addr'] = mgmt_ip.get()
               node[local_hostname]['node_type'] = 'generic'
               node[local_hostname]['neighbors'] = []
               extra_nodes.append(deepcopy(node))
               node.clear()
            else:
               log.debug('%s blacklisted - not creating', local_hostname)     


         remote_hostname = entry[2]
         if remote_hostname in serials:
            # Remote hostname is in CVP inventory
            remote_hostname = serials[entry[2]]
         elif any(remote_hostname in x for x in extra_nodes):
            # Generic node already created
            pass
         else:
            if remote_hostname not in blacklist:
               log.debug("Creating generic node: %s" % entry[2])
               node[remote_hostname] = {}
               node[remote_hostname]['ip_addr'] = mgmt_ip.get()
               node[remote_hostname]['node_type'] = 'generic'
               node[remote_hostname]['neighbors'] = []
               extra_nodes.append(deepcopy(node))
               node.clear()
            else:
               log.debug('%s blacklisted - not creating', remote_hostname)
      else:
         log.debug('Skipping VX')

      if local_hostname not in edgeSet:
         edgeSet[local_hostname] = []

      edgeSet[ local_hostname ].append( {'neighborDevice':remote_hostname,'neighborPort':entry[3],'port':entry[1]  }   )

   return edgeSet, extra_nodes


def build_output(cvp_version, log):
   output_data = {}
   output_data['cvp'] = {}
   output_data['cvp']['username'] = 'root'
   output_data['cvp']['password'] = 'cvproot'
   if cvp_version == 'cvaas':
      output_data['cvp']['version'] = '2022.2.0'
      log.warning('You are exporting from CVaaS - setting CVP version to: %s', output_data['cvp']['version'] )
   else:
      output_data['cvp']['version'] = cvp_version
   output_data['cvp']['instance'] = 'singleinstance'
   
   
   output_data['generic'] = {}
   output_data['generic']['version'] = 'CentOS-8-8.2.2004'
   output_data['generic']['username'] = 'ansible'
   output_data['generic']['password'] = 'ansible'

   return output_data


def main():
   
   timestamp = time.strftime("%Y%m%d-%H%M")
   logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
   mainLogger = logging.getLogger('cvp-atc-exporter')
   # We append to the log if it already exists, if not create the file
   fh = logging.FileHandler('cvp-atc-exporter'+timestamp+'.log', mode='a+')
   # Set the log level going to the file
   fh.setLevel(logging.DEBUG)
   fh.setFormatter(logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
   mainLogger.addHandler(fh)
   # Console logging
   ch = logging.StreamHandler(sys.stdout)
   ch.setLevel(logging.INFO)
   ch.setFormatter(logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
   # Dial the imports down
   temp = logging.getLogger('urllib3.connectionpool')
   temp.setLevel(logging.WARNING)
   temp = logging.getLogger('cvprac')
   temp.setLevel(logging.WARNING)
   mainLogger.addHandler(ch)
   mainLogger.propagate = False

   mainLogger.info('Script started')

   mainLogger.debug('Processing input arguments')
   parser = argparse.ArgumentParser(prog='CVP to ATC Exporter',
      description='This script exports the nodes, links and version information from CVP into a YAML file for import to Arista Cloud Test')

   parser.add_argument('-t','--test', action='store_true', default=False, 
      help='If --test is set, we will not connect to CVP but instead try and use local json files as our source data. Disabled by default.')
   parser.add_argument('--export', action='store_true', default=False, 
      help='Store the responses from CVP as json data locally, for later testing. Disabled by default.')
   parser.add_argument('-o', '--output', default='generated_act_topology.yaml', 
      help='Output file name, default is: generated_act_topology.yaml',dest='output_file')
   parser.add_argument('--streaming', action='store_true', default=False, 
      help='Only add nodes that are actively streaming from the CVP inventory. Any nodes (and their links) that are not streaming, will not be created. Disabled by default.')
   parser.add_argument('--create-generic', action='store_true', default=True, 
      help='If there are non-CVP nodes whose presence is inferred from the link data, create them as generic linux hosts. *Enabled* by default')
   parser_group = parser.add_mutually_exclusive_group(required=True)
   parser_group.add_argument('-u', '--username', help='username if using on-prem user accounts',dest='username')
   parser_group.add_argument('--token', help='API token, required if on CVaaS', dest='token')
   parser.add_argument('--cvp', action='append', required=True, help='Hostname(s) or IP(s) of the CVP instance to connect to')
   parser.add_argument('-p', '--password', dest='password', default=None, help='Password for connecting to CVP, when not using API tokens')

   args = parser.parse_args()


   # Set global flags
   global TEST_MODE
   TEST_MODE = args.test
   global EXPORT_CVP_DATA
   EXPORT_CVP_DATA = args.export
   global GENERATE_GENERIC
   GENERATE_GENERIC = args.create_generic

   if args.token is None:
      if args.password is None:
         args.password = getpass(prompt='Please enter CVP password: ')

   if TEST_MODE is False:
      mainLogger.info('Attempting to connect to CVP')
      client = CvpClient()
      if args.token is not None:
         client.connect(args.cvp, username='', password='', is_cvaas=True, api_token=args.token)
      else:
         client.connect(args.cvp, args.username, args.password)

      mainLogger.info('Collecting CVP info')
      cvp_info = client.api.get_cvp_info()
      mainLogger.info('Collecting device inventory')
      inventory = client.api.get_inventory()
      mainLogger.info('Collecting link topologies')
      raw_topology = client.get('/api/v1/rest/analytics/network/v1/topology/edges')

      if EXPORT_CVP_DATA is True:
         mainLogger.info('Exporting collected data to json')
         json_object = json.dumps(cvp_info,indent=4)
         with open('cvp.json','w') as outfile:
            outfile.write(json_object)

         json_object = json.dumps(inventory,indent=4)
         with open('inventory.json','w') as outfile:
            outfile.write(json_object)

         json_object = json.dumps(raw_topology,indent=4)
         with open('topology.json','w') as outfile:
            outfile.write(json_object)

   else:
      try:
         mainLogger.warning('Running in test mode... Loading local files...')
         with open('cvp.json','r') as openfile:
            cvp_info = json.load(openfile)
         with open('inventory.json','r') as openfile:
            inventory = json.load(openfile)
         with open('topology.json','r') as openfile:
            raw_topology = json.load(openfile)
      except Exception as e:
         mainLogger.error('Unable to open local data: %s', e)
         return 1


   mgmt_ip_block = ipGenerator()

   mainLogger.info("Building node list, and mapping hostname to serial numbers")
   nodes,serialTable,blacklist = build_node_list(inventory, mgmt_ip_block, mainLogger, streaming_active=args.streaming)
   mainLogger.info("Successfully mapped %d nodes, and %d serial numbers", len(nodes), len(serialTable))

   mainLogger.info("Mapping links")
   edgeList, genericNodes = generate_edges(raw_topology,serialTable, mgmt_ip_block, mainLogger, blacklist=blacklist)
   mainLogger.info("Successfully mapped %d links, and found %d generic/not-in-inventory nodes",  sum([len(element) for element in edgeList]), len(genericNodes))

   mainLogger.info("Building final datastructure")
   mainLogger.debug("Creating CVP header")
   output_data = build_output(cvp_info['version'], mainLogger)


   mainLogger.debug("Populating node list")
   output_data['nodes'] = deepcopy(nodes)
   if GENERATE_GENERIC is True:
      mainLogger.info("Adding generic nodes to inventory")
      output_data['nodes'].extend( deepcopy(genericNodes))

   # Insert CVP1
   cvp1 = {}
   cvp1['cvp1'] = {}
   cvp1['cvp1']['ip_addr'] = '192.168.0.5'
   cvp1['cvp1']['node_type'] = 'cvp'
   cvp1['cvp1']['neighbors'] = []
   output_data['nodes'].append(cvp1)

   mainLogger.debug("Adding links to inventory")

   for entry in output_data['nodes']:
      for node in entry:
         if node != 'cvp1':
            if node in edgeList:
               entry[node]['neighbors'] = deepcopy(edgeList[node])
               # Inject CVP link
               entry[node]['neighbors'].append( {'neighborDevice':'cvp1','neighborPort':'Management0','port':'Management1' } )
               # CVP1 is the last added node
               output_data['nodes'][-1]['cvp1']['neighbors'].append( {'neighborDevice':node,'neighborPort':'Management1','port':'Management0' } )
            else:
               mainLogger.debug('%s has no links that we can find', node)
         else:
            mainLogger.debug('CVP1 statically generated')

   mainLogger.info('Writing output yaml')
   with open(args.output_file,'w') as output_file:
      temp = yaml.safe_dump(output_data, output_file, sort_keys=False)
   mainLogger.info('Export completed')

   return 0


if __name__ == "__main__":
   main()