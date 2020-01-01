#!/usr/bin/env python

from ldaptor.protocols.pureldap import *
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from functools import partial
import sys
import base64
import re
from typing import Any, Callable, Collection, Union


def try_log_response(resp: Any) -> None:
    """
    Try to log a response we're sending out but fail gracefully if __repr__ fails
    due to binary data in parameters
    """
    try:
        log.msg("Response => " + repr(resp))
    except UnicodeDecodeError:
        log.msg('Binary data')


def handle_bind_request(request: LDAPProtocolRequest, controls, reply: Callable) -> defer.Deferred:
    """
    Allow binding with user@DOMAIN instead of full dn uid=user,...,dc=domain
    """
    request_dn = request.dn.decode()
    if '@' in request_dn and ',' not in request_dn:
        user, domain = request_dn.split('@')
        dcs = ','.join(f'dc={dc}' for dc in domain.split('.'))
        dn = f"uid={user},cn=users,cn=accounts,{dcs}"
        request.dn = dn.encode()
        log.msg("Modified  => " + repr(request))
    return defer.succeed((request, controls))


def send_object(objectName: Union[bytes, str], attributes: Collection, reply: Callable) -> None:
    """
    A shortcut to send an LDAPSearchResult object to the client
    """
    entry = LDAPSearchResultEntry(objectName=objectName, attributes=attributes)
    try_log_response(entry)
    reply(entry)
    done = LDAPSearchResultDone(resultCode=0)
    try_log_response(done)
    reply(done)


def translate_attributes_k(attributes: list, mapping: dict) -> list:
    new_attributes = []
    for attribute in attributes:
        if attribute in mapping.keys():
            new_attributes.append(mapping[attribute])
        else:
            new_attributes.append(attribute)
    return new_attributes


def translate_attributes_kv(attributes: list, mapping: dict) -> list:
    new_attributes = []
    for key, values in attributes:
        if key in mapping.keys():
            new_attributes.append((mapping[key], values,))
        else:
            new_attributes.append((key, values,))
    return new_attributes


def base_attribute_query(request: LDAPSearchRequest, attribute: bytes) -> bool:
    return (
        request.scope == 0 and
        len(request.attributes) == 1 and
        request.attributes[0] == attribute and
        request.baseObject.startswith(b'dc=')
    )


def get_dcs(dn: bytes) -> str:
    return re.search('.*?,(dc=.*)', dn.decode()).group(1)


def get_domain(dn: bytes) -> str:
    """
    dc=domain,dc=com --> domain.con
    """
    dcs = get_dcs(dn)
    return '.'.join([dc[3:] for dc in dcs.split(',')])


def to_string(value: Union[BEROctetString, bytes, str]) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, BEROctetString):
        value = value.value
        return to_string(value)


def handle_search_request(request: LDAPSearchRequest,
                          controls, reply: Callable) -> Union[defer.Deferred, None]:
    if request.baseObject.decode().startswith('CN=Partitions,CN=Configuration,'):
        return send_object(
            objectName=f'CN=ESAV.FI,{request.baseObject}',
            attributes=[
                ('objectClass', ['top', 'crossRef']),
                ('netbiosname', [get_domain(request.baseObject).upper()]),
            ], reply=reply)

    if base_attribute_query(request, b'objectSid'):
        return send_object(
            objectName=request.baseObject,
            attributes=[
                ('objectSid', [base64.b64decode('AQQAAAAAAAUVAAAABszE9hHPqWc9qhkd')]),
            ], reply=reply)

    if base_attribute_query(request, b'objectGUID'):
        return send_object(
            objectName=request.baseObject,
            attributes=[
                ('objectGUID', [base64.b64decode('PJ7qGgyLbkqXIY1XOjVyBQ==')]),
            ], reply=reply)

    if base_attribute_query(request, b'name'):
        return send_object(
            objectName=request.baseObject,
            attributes=[
                ('name', [get_domain(request.baseObject)])
            ], reply=reply)

    if isinstance(request.filter, LDAPFilter_or):
        for sub_filter in request.filter:
            assert isinstance(sub_filter, LDAPFilter_equalityMatch)
            print(type(sub_filter.assertionValue))

            if to_string(sub_filter.attributeDesc).lower() == 'objectclass' and \
                to_string(sub_filter.assertionValue).lower() == 'container':
                request.filter.append(LDAPFilter_equalityMatch(
                    attributeDesc=BEROctetString(value='objectClass'),
                    assertionValue=BEROctetString(value='nsContainer')
                ))

        log.msg("Modified => " + repr(request))


    request.attributes = translate_attributes_k(request.attributes, {
        "objectGUID": "ipaUniqueID"
    })

    return defer.succeed((request, controls))


class LoggingProxy(ProxyBase):
    def handleBeforeForwardRequest(self, request: LDAPProtocolRequest,
                                   controls, reply: Callable) -> Union[defer.Deferred, None]:
        log.msg("Request => " + repr(request))

        if isinstance(request, LDAPBindRequest):
            return handle_bind_request(request, controls, reply)

        elif isinstance(request, LDAPSearchRequest):
            return handle_search_request(request, controls, reply)

    def handleProxiedResponse(self, response: LDAPProtocolResponse,
                              request: LDAPProtocolRequest, controls) -> Union[defer.Deferred, None]:
        if isinstance(response, LDAPSearchResultEntry):

            response.attributes = translate_attributes_kv(response.attributes, {
                'ipaUniqueID': 'ObjectGUID'
            })


            # Add distinguishedname
            assert isinstance(request, LDAPSearchRequest)
            if b'distinguishedName' in request.attributes:
                response.attributes.append(('distinguishedName', (response.objectName,)))

        log.msg("Response => " + repr(response))
        return defer.succeed(response)


LDAPBindRequest.__repr__ = lambda self: self.__class__.__name__ + '(*auth*)'

if __name__ == '__main__':
    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'tls:host=ipa.tre.esav.fi:port=636'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def build_protocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = build_protocol
    reactor.listenTCP(10389, factory)
    reactor.run()
