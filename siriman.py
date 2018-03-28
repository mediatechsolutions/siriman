#!/usr/bin/env python
import os
import argparse
import logging
import subprocess
import xml.etree.ElementTree as ET
import yaml


logger = logging.getLogger()
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DETAIL = logging.INFO - 1
DEBUG = logging.DEBUG
VERBOSITIES = [ERROR, WARNING, INFO, DETAIL, DEBUG]

def configure_logging(verbosity):
    level = VERBOSITIES[min(int(verbosity), len(VERBOSITIES) -1)]
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)

log_error = logger.error
log_warning = logger.warning
log_info = logger.info
log_detail = lambda x: logger.log(DETAIL, x)
log_debug = logger.debug
log_exception = logger.exception


class Constants:
    ACTION_SOURCES='sources'
    ACTION_DISCOVER='discover'
    ACTIONS = (
        ACTION_SOURCES,
        ACTION_DISCOVER,
    )


class Active:
    def as_dict(self):
        return vars(self)

class HostActive(Active):
    code = 'HW'

    def __init__(self, name, filename=None):
        self.name = name
        self.addresses = list()
        self.hostnames = list()
        self.os = None
        self.state = None

    def __str__(self):
        return "{HOST %s - %s}" % (self.name, self.state)

    def add_address(self, address, address_type):
        self.addresses.append(
            {
                "address": address,
                "type": address_type,
            }
        )
   
    def add_hostname(self, hostname, host_type):
        self.hostnames.append(
            {
                "hostname": hostname,
                "type": host_type,
            } 
        )

        

class ServiceActive(Active):
    code = 'S'

    def __init__(self, name, filename=None):
        self.name = name
        self.program = None
        self.product = None
        self.version = None
        self.os = None
        self.state = None
        self.host = None
        self.address = None


class YamlPersistence:
    def __init__(self, directory):
        self.directory = directory
        self._template_cache = None

    @property
    def sourcesfile(self):
        return os.path.join(self.directory, 'sources.yaml')

    @property
    def templatefile(self):
        return os.path.join(os.path.dirname(__file__), 'templates', 'magerit_v3.yaml')

    def read(self, filename):
        with open(filename) as fd:
            return yaml.load(fd)

    def write(self, filename, data):
        with open(filename, 'w+') as fd:
            yaml.dump(data, fd, default_flow_style=False, encoding=('utf-8'), allow_unicode=True)

    def load_sources(self):
        for data in self.read(self.sourcesfile):
            yield source_builder(data, self.sourcesfile)
       
    def load_template(self):
        if self._template_cache == None:
            self._template_cache = self.read(self.templatefile)
        return self._template_cache

    def get_active_type_for_code(self, code):
        template = self.load_template()
        for active in template['active_types']:
            if active['code'] == code:
                return active
        return None

    def get_risks_for_active_type(self, active_type, language):
        template = self.load_template()
        active_type = self.get_active_type_for_code(active_type)
        for group in template['threat_groups']:
            for threat in group['threats']:
               if active_type in threat['active_types']:
                    yield dict(
                        code=threat['code'],
                        title=threat['title'][language],
                        probability=None,
                        impact=None, 
                        # dimensions=[
                        #     dict(code=x['code'], title=x['title'][language])
                        #     for x in threat['dimensions']
                        # ],
                    )

    def write_active(self, active):
        filename = os.path.join(self.directory, "%s_%s.yaml" % (active.code, active.name))
        if os.path.exists(filename):
            log_debug("File %s already exists. Ignoring." % filename)
        else:
            log_debug("Writting active %s to file %s" % (active.name, filename))
            self.write(filename, active.as_dict())
 
class Source:
    pass


class URLSource(Source):
    def __init__(self, name, filename=None):
        self.name = name
        self.filename = filename
        self.addresses = []

    @classmethod
    def build_from_dict(self, data, filename):
        result = URLSource(data['name'], filename)
        result.addresses = data.get('addresses')  or []  # fixme: sanitize
        return result

    def __str__(self):
        return "URL:%s" % self.name

    def discover(self, callback):
        """Discover new actives and call Callback with any of them as only argument"""
        log_debug("discovering")
        for address in self.addresses:
            log_info("Discover for address %s" % address)
            ports = ','.join(address['ports']) if address.get('ports') else '1-65535'
            log_debug("Scanning %s with ports %s" % (address, ports))
            data = subprocess.check_output(("nmap -sV -sT -Pn -oX - %s -p %s" % (address['address'], ports)).split())
            root = ET.fromstring(data)
            for host in root.iter('host'):
                newhost = HostActive(self.name)
                newhost.state = host.find('status').get('state')
                for addr in host.iter("address"):
                    newhost.add_address(addr.get('addr'), addr.get('addrtype'))
                for name in host.iter("hostname"):
                    newhost.add_hostname(name.get('name'), name.get('type'))
                for port in host.iter("port"):
                    service = ServiceActive("%s_%s_%s" % (address['address'], port.get('protocol'), port.get('portid')))
                    svc = port.find('service')
                    service.program = svc.get('name')
                    service.product = svc.get('product')
                    service.version = svc.get('version')
                    service.state = port.find('state').get('state')
                    service.os = svc.get('ostype')
                    service.address = address
                    callback(service)
                callback(newhost)
            


def source_builder(data, filename):
    classes = dict(
        url=URLSource,
    )
    _type = data.get('type')
    if _type in classes:
        return classes[_type].build_from_dict(data, filename)
    raise Exception("Invalid type %s for source %s in file %s" % (_type, data['name'], data.get('name'), filename))


class Siriman:
    def __init__(self, args, persistence):
        self.args = args
        self.persistence = persistence
        self.risks = None
    
        if not os.path.exists(args.directory):
            os.makedirs(args.directory)

    def show_sources(self):
        sources = self.persistence.load_sources()

        for source in sources:
            print("\t- %s" % source)
       
    def discover(self):
        def save_active(active):
            log_debug("Discovered active %s" % active.name)
            active.risks = list(self.persistence.get_risks_for_active_type(active.code, self.args.language))
            self.persistence.write_active(active)
            
        sources = self.persistence.load_sources()
        for source in sources:
            if not self.args.sources or source in self.args.sources:
                source.discover(save_active)

    def initialize(self):
        self.load_risks()

    def load_risks(self):
        self.risks = yaml.load(self.args.risklist)

    def create_risks_file(self):
        result = list()
        for risk in self.risks:
            if self.args.language not in risk['description']:
                raise Exception("Language not supported")
            result.append(
                dict(
                    code=risk['code'],
                    description=risk['description'][self.args.language],
                )
            )
        self.persistence.write(self.risksfile, result)


def main():
    parser = argparse.ArgumentParser(description='Simple Risk Manager')
    parser.add_argument(
        'action',
        choices=Constants.ACTIONS,
        help="Action to be performed"
    )
    parser.add_argument(
        '--templates', 
        default=None,
        help='Directory to find templates; if a template is not found, it will be searched internally.'
    )
    parser.add_argument(
        '--language', 
        default="es",
        help='Language to be used'
    )
    parser.add_argument(
        '-d', '--directory',
        default="risks",
        help='Work directory'
    )
    parser.add_argument(
        '--sources',
        nargs='*',
        help='Work directory'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        dest='verbosity',
        default=0,
        help='Increase verbosity. Several increases even more.'
    )
    args = parser.parse_args()

    configure_logging(args.verbosity)

    persistence = YamlPersistence(args.directory)
    siriman = Siriman(args, persistence)
    if args.action == Constants.ACTION_SOURCES:
        siriman.show_sources()
    elif args.action == Constants.ACTION_DISCOVER:
        siriman.discover()
    else:
        log_error("Action '%s' is not supported." % args.action)


if __name__ == '__main__':
    main()
