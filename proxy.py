#!/usr/bin/env python

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from functools import partial
import sys
import base64


def try_log(message):
    try:
        log.msg(message)
    except UnicodeDecodeError:
        log.msg('Binary data')


def handle_bind_request(request, controls, reply):
    request_dn = request.dn.decode()
    if '@' in request_dn and ',' not in request_dn:
        user, domain = request_dn.split('@')
        dcs = ','.join(f'dc={dc}' for dc in domain.split('.'))
        dn = f"uid={user},cn=users,cn=accounts,{dcs}"
        request.dn = dn.encode()
        log.msg("Modified  => " + repr(request))
    return defer.succeed((request, controls))


def send_object(objectName, attributes, reply) -> None:
    entry = pureldap.LDAPSearchResultEntry(objectName=objectName, attributes=attributes)
    try_log("Response => " + repr(entry))
    reply(entry)
    done = pureldap.LDAPSearchResultDone(resultCode=0)
    try_log("Response => " + repr(done))
    reply(done)


def translate_attributes_k(attributes: list, mapping: dict):
    new_attributes = []
    for attribute in attributes:
        if attribute in mapping.keys():
            new_attributes.append(mapping[attribute])
        else:
            new_attributes.append(attribute)
    return new_attributes


def translate_attributes_kv(attributes: list, mapping: dict):
    new_attributes = []
    for key, values in attributes:
        if key in mapping.keys():
            new_attributes.append((mapping[key], values,))
        else:
            new_attributes.append((key, values,))
    return new_attributes


def handle_search_request(request, controls, reply):
    bo = request.baseObject.decode()
    if bo.startswith('CN=Partitions,CN=Configuration,'):
        return send_object(
            objectName='CN=ESAV.FI,CN=Partitions,CN=Configuration,DC=esav,DC=fi',
            attributes=[
                ('objectClass', ['top', 'crossRef']),
                ('netbiosname', ['ESAV.FI']),
            ], reply=reply)

    if len(request.attributes) == 1 and request.attributes[0] == b'objectSid':
        return send_object(
            objectName='DC=esav,DC=fi',
            attributes=[
                ('objectSid', [base64.b64decode('AQQAAAAAAAUVAAAABszE9hHPqWc9qhkd')]),
            ], reply=reply)

    if len(request.attributes) == 1 and request.attributes[0] == b'objectGUID':
        return send_object(
            objectName='DC=esav,DC=fi',
            attributes=[
                ('objectGUID', [base64.b64decode('PJ7qGgyLbkqXIY1XOjVyBQ==')]),
            ], reply=reply)

    request.attributes = translate_attributes_k(request.attributes, {
        "objectGUID": "ipaUniqueID"
    })

    return defer.succeed((request, controls))


class LoggingProxy(ProxyBase):
    def handleBeforeForwardRequest(self, request, controls, reply):
        log.msg("Request => " + repr(request))

        if isinstance(request, pureldap.LDAPBindRequest):
            return handle_bind_request(request, controls, reply)

        elif isinstance(request, pureldap.LDAPSearchRequest):
            return handle_search_request(request, controls, reply)

    """
    A simple example of using `ProxyBase` to log requests and responses.
    """
    def handleProxiedResponse(self, response, request, controls):
        """
        Log the representation of the responses received.
        """
        if isinstance(response, pureldap.LDAPSearchResultEntry):

            response.attributes = translate_attributes_kv(response.attributes, {
                'ipaUniqueID': 'ObjectGUID'
            })

            # Add distinguishedname
            if b'distinguishedName' in request.attributes:
                response.attributes.append(('distinguishedName', (response.objectName,)))

        log.msg("Response => " + repr(response))
        return defer.succeed(response)


def ldapBindRequestRepr(self):
    l=[]
    l.append('version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=****')
    if self.tag!=self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__+'('+', '.join(l)+')'

pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr

if __name__ == '__main__':
    """
    Demonstration LDAP proxy; listens on localhost:10389 and
    passes all requests to localhost:8080.
    """
    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'tls:host=ipa.tre.esav.fi:port=636'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(10389, factory)
    reactor.run()