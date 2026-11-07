#!/usr/bin/env python3
"""Render, never apply, the per-install egress policy after scope is confirmed."""
import argparse
import ipaddress
import json
import re

parser = argparse.ArgumentParser()
parser.add_argument('--namespace', required=True)
parser.add_argument('--web-app-label', required=True)
parser.add_argument('--router-namespace', required=True)
parser.add_argument('--router-app-label', required=True)
parser.add_argument('--temporal-app-label', required=True)
parser.add_argument('--postgres-app-label', required=True)
parser.add_argument('--allowed-https-ip', action='append', default=[], required=True,
                    help='An authorized target, approved Git host or gateway IP; repeat for every address')
args = parser.parse_args()
for label in [args.namespace, args.web_app_label, args.temporal_app_label, args.postgres_app_label, args.router_namespace, args.router_app_label]:
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', label):
        parser.error('Use verified Kubernetes namespace and workload label values')
peers = []
for raw in args.allowed_https_ip:
    address = ipaddress.ip_address(raw)
    if not address.is_global or address.version == 6 and (address.ipv4_mapped or address.sixtofour or address.teredo):
        parser.error('Only explicit public HTTPS addresses are supported for this trial')
    peers.append({'ipBlock': {'cidr': str(address) + ('/32' if address.version == 4 else '/128')}})
dns = {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
               'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
       'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]}


def policy(name, app, egress):
    return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': name, 'namespace': args.namespace},
            'spec': {'podSelector': {'matchLabels': {'app.kubernetes.io/name': app}},
                     'policyTypes': ['Egress'], 'egress': egress}}


def service(label, ports):
    return {'to': [{'podSelector': {'matchLabels': {'app.kubernetes.io/name': label}}}],
            'ports': [{'protocol': 'TCP', 'port': port} for port in ports]}


items = [
    policy('shannon-web-egress', args.web_app_label,
           [dns, service(args.temporal_app_label, [7233]), {'to': peers, 'ports': [{'protocol': 'TCP', 'port': 443}]}]),
    policy('shannon-temporal-egress', args.temporal_app_label,
           [dns, service(args.postgres_app_label, [5432]), service(args.temporal_app_label, [7233, 7234, 7235, 7239, 6933, 6934, 6935, 6939])]),
    policy('shannon-postgres-egress', args.postgres_app_label, [])
]
# SSO headers are a trusted-proxy contract, not cryptographic assertions.
# Only the verified platform router may enter the Web service.
items[0]['spec']['policyTypes'].append('Ingress')
items[0]['spec']['ingress'] = [{'from': [{
    'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': args.router_namespace}},
    'podSelector': {'matchLabels': {'app.kubernetes.io/name': args.router_app_label}}
}], 'ports': [{'protocol': 'TCP', 'port': 8080}]}]
for item, sources in [(items[1], [service(args.web_app_label, [7233]), service(args.temporal_app_label, [7233, 7234, 7235, 7239, 6933, 6934, 6935, 6939])]),
                      (items[2], [service(args.temporal_app_label, [5432])])]:
    item['spec']['policyTypes'].append('Ingress')
    item['spec']['ingress'] = [{'from': rule['to'], 'ports': rule['ports']} for rule in sources]
print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}, indent=2))
