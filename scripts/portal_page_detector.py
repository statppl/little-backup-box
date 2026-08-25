#!/usr/bin/env python

# Author: Stefan Saam, github@saams.de

#######################################################################
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#######################################################################

# script is started by lib_comitup.py when state is set to CONNECTED
# As long state is CONNECTED, it tries to find out the link to a
# portal page. This is written to const_NETWORK_PORTAL_PAGE_LINK_FILE

import os
import pwd
import requests
import subprocess
import time
from urllib.parse import urlsplit, urlunsplit

import lib_comitup
import lib_setup

class portal_page_detector(object):
	def __init__(self):
		self.__setup	= lib_setup.setup()

		self.__const_NETWORK_PORTAL_PAGE_LINK_FILE	= self.__setup.get_val('const_NETWORK_PORTAL_PAGE_LINK_FILE')

		self.test_URL								='http://connectivitycheck.gstatic.com/generate_204'

		self.portal_interface						= None

	def detect(self, interface):
		try:
			result	= subprocess.run(
				[
					'/usr/bin/curl',
					'--silent',
					'--show-error',
					'--interface', interface,
					'--max-time', '5',
					'--output', '/dev/null',
					'--write-out', '%{http_code}\n%{redirect_url}',
					self.test_URL
				],
				capture_output	= True,
				text			= True
			)

			if result.returncode != 0:
				return False, None

			lines	= result.stdout.splitlines()

			status_code	= int(lines[0]) if lines else 0
			portal_url	= lines[1].strip() if len(lines) > 1 else ''

			if status_code == 204:
				return True, None

			if portal_url:
				return True, portal_url

			return False, None

		except Exception as e:
			print(f'Portal detection on {interface} failed: {e}')
			return False, None

	def get_wifi_interfaces(self):
		interfaces = []

		try:
			for interface in os.listdir('/sys/class/net'):
				if not os.path.isdir(f'/sys/class/net/{interface}/wireless'):
					continue

				try:
					with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
						if f.read().strip() != 'up':
							continue
				except:
					continue

				interfaces.append(interface)

		except Exception as e:
			print(f'Error detecting WiFi interfaces: {e}')

		return interfaces

	def read_linkfile(self):
		try:
			with open(self.__const_NETWORK_PORTAL_PAGE_LINK_FILE, 'r') as f:
				portal_url = f.read().strip()

			return portal_url if portal_url else None

		except FileNotFoundError:
			return None

		except Exception as e:
			print(f'Error reading "{self.__const_NETWORK_PORTAL_PAGE_LINK_FILE}": {e}')
			return None

	def write_linkfile(self, portal_url):
		try:
			with open(self.__const_NETWORK_PORTAL_PAGE_LINK_FILE, 'w') as f:
				f.write(portal_url if portal_url is not None else '')

		except Exception as e:
			print(f'Error writing to "{self.__const_NETWORK_PORTAL_PAGE_LINK_FILE}": {e}')
			return False

		try:
			user_info	= pwd.getpwnam('www-data')
			uid			= user_info.pw_uid
			gid			= user_info.pw_gid
			os.chown(self.__const_NETWORK_PORTAL_PAGE_LINK_FILE, uid, gid)

		except Exception as e:
			print(f'Error in chown "{self.__const_NETWORK_PORTAL_PAGE_LINK_FILE}": {e}')

		return True

	def update_apache_config(self, portal_url):
		conf_file	= '/etc/apache2/includes/portalpage.conf'
		tmp_file	= conf_file + '.new'

		if portal_url is None:
			config	= '# No captive portal detected\n'

		else:
			try:
				u	= urlsplit(portal_url)

				if u.scheme not in ('http', 'https'):
					print(f'Unsupported portal URL scheme: {u.scheme}')
					return False

				if not u.hostname:
					print(f'Portal URL contains no hostname: {portal_url}')
					return False

				if any(c in portal_url for c in ('\r', '\n', '"', '\\')):
					print(f'Invalid character in portal URL: {portal_url}')
					return False

				origin		= f'{u.scheme}://{u.netloc}/'
				path		= u.path if u.path else '/'
				target		= urlunsplit((u.scheme, u.netloc, path, u.query, ''))

				ssl_proxy	= ''
				if u.scheme == 'https':
					ssl_proxy	= 'SSLProxyEngine On\n'

				config		= f'''# Automatically generated - DO NOT EDIT

{ssl_proxy}ProxyPassMatch   "^/portalpage/?()$" "{target}$1"
ProxyPassReverse "/portalpage" "{target}"

ProxyPass        "/portalpage/" "{origin}"
ProxyPassReverse "/portalpage/" "{origin}"

<LocationMatch "^/portalpage(?:/|$)">
	RequestHeader unset Accept-Encoding
	SetOutputFilter proxy-html

	ProxyHTMLURLMap "{origin}" "/portalpage/"
	ProxyHTMLURLMap "/" "/portalpage/"
</LocationMatch>

ProxyPassReverseCookiePath "/" "/portalpage/"
'''

			except Exception as e:
				print(f'Error creating Apache portal config: {e}')
				return False

		old_config	= None

		try:
			if os.path.exists(conf_file):
				with open(conf_file, 'r') as f:
					old_config	= f.read()

			with open(tmp_file, 'w') as f:
				f.write(config)

			os.replace(tmp_file, conf_file)

			result	= subprocess.run(
				['/usr/sbin/apache2ctl', 'configtest'],
				capture_output	= True,
				text			= True
			)

			if result.returncode != 0:
				print('Apache configtest failed:')
				print(result.stdout)
				print(result.stderr)

				if old_config is None:
					with open(conf_file, 'w') as f:
						f.write('# No captive portal detected\n')
				else:
					with open(conf_file, 'w') as f:
						f.write(old_config)

				return False

			result	= subprocess.run(['sudo', '/usr/bin/systemctl', 'reload', 'apache2'],
				capture_output	= True,
				text			= True
			)

			if result.returncode != 0:
				print('Apache reload failed:')
				print(result.stdout)
				print(result.stderr)

				if old_config is None:
					with open(conf_file, 'w') as f:
						f.write('# No captive portal detected\n')
				else:
					with open(conf_file, 'w') as f:
						f.write(old_config)

				return False

			return True

		except Exception as e:
			print(f'Error updating Apache portal config: {e}')

			try:
				if os.path.exists(tmp_file):
					os.unlink(tmp_file)
			except:
				pass

			return False

	def update_portal(self, portal_url):
		old_portal_url = self.read_linkfile()

		if old_portal_url == portal_url:
			return True

		print(f'Portal page changed: {old_portal_url} -> {portal_url}')

		if not self.update_apache_config(portal_url):
			print('Apache portal configuration could not be updated')
			return False

		if not self.write_linkfile(portal_url):
			print('Portal link file could not be updated')
			return False

		return True

	def remove_own_portal(self, portal_url):
		current_portal_url = self.read_linkfile()

		if current_portal_url != portal_url:
			print(
				f'Portal configuration already changed: '
				f'{portal_url} -> {current_portal_url}'
			)
			return

		self.update_portal(None)

	def run(self):
		comitup		= lib_comitup.comitup()

		timeout		= 30
		retry_delay	= 3
		end_time	= time.monotonic() + timeout

		while time.monotonic() < end_time:

			state	= comitup.get_status()['state']
			if state != 'CONNECTED':
				time.sleep(retry_delay)
				continue

			interfaces = self.get_wifi_interfaces()

			for interface in interfaces:
				success, portal_url = self.detect(interface)

				if not success:
					continue

				if portal_url is not None:
					print(f'Portal page detected on {interface}: {portal_url}')

					if self.read_linkfile() == portal_url:
						print(f'Portal page already configured: {portal_url}')
						return None

					if not self.update_portal(portal_url):
						return None

					self.portal_interface	= interface
					return portal_url

				# HTTP 204 -> auf diesem Interface kein Portal.
				# Andere WLAN-Interfaces trotzdem noch prüfen.

			time.sleep(retry_delay)

		print('No captive portal detected')
		return None

if __name__ == "__main__":
	pd			= portal_page_detector()

	portal_url	= pd.run()

	if portal_url is not None:
		while True:
			time.sleep(10)

			comitup = lib_comitup.comitup()

			state = comitup.get_status()['state']

			if state is False:
				continue

			if state != 'CONNECTED':
				print(f'Portal page no longer connected: {location}')
				pd.remove_own_portal(location)
				break

			success, current_portal_url = pd.detect(pd.portal_interface)

			# Do not remove config on temp error
			if not success:
				continue

			# own portal still exists
			if current_portal_url == portal_url:
				continue

			# else: internet access or other portal
			print(
				f'Portal page no longer available: '
				f'{portal_url} -> {current_portal_url}'
			)

			pd.remove_own_portal(portal_url)
			break
