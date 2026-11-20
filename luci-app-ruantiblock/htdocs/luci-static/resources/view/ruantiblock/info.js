'use strict';
'require fs';
'require poll';
'require ui';
'require view';
'require view.ruantiblock.tools as tools';

document.head.append(E('style', {'type': 'text/css'},
`
.log-entries-count {
	margin: 0 0 5px 5px;
	font-weight: bold;
	opacity: 0.7;
}
`));

return view.extend({
	pollInterval   : L.env.pollinterval,

	secToTimeString(value) {
		let string = '';
		if(/^\d+$/.test(value)) {
			value = Number(value);
			let hours = 0, mins = 0, sec = 0, rest = value;
			if(value >= 3600) {
				hours = Math.floor(value / 3600);
				rest  = value % 3600;
			};
			if(rest >= 60) {
				mins = Math.floor(rest / 60);
				rest = rest % 60;
			};
			sec = rest;
			if(hours > 0) {
				string = string + hours + _('h');
			};
			if(mins > 0) {
				string = string + ' ' + mins + _('m');
			};
			string = string + ' ' + sec + _('s');
		};
		return string;
	},

	formatNftJson(data) {
		let output = { 'rules': [] };
		if(data.rules.nftables && data.rules.nftables.length > 1) {
			for(let i of data.rules.nftables) {
				if(!i.rule) {
					continue;
				};
				let set, bytes;
				i.rule.expr.forEach(e => {
					if(e.match && e.match.left && e.match.left.payload) {
						set = e.match.right.replace('@', '');
					}
					else if(e.counter) {
						bytes = e.counter.bytes;
					};
				});
				output.rules.push([ set, bytes ]);
			};

			function parseDnsmasqData(set) {
				let sArray = [];
				if(set.nftables && set.nftables.length > 1) {
					set.nftables.forEach(e => {
						if(e.set && e.set.elem) {
							e.set.elem.forEach(i => {
								if(i.elem) {
									sArray.push([ i.elem.val, i.elem.expires ]);
								};
							});
						};
					});
				};
				return sArray;
			};

			if(data.dnsmasq) {
				output.dnsmasq = parseDnsmasqData(data.dnsmasq);
			};
			if(data.dnsmasq_bypass) {
				output.dnsmasq_bypass = parseDnsmasqData(data.dnsmasq_bypass);
			};
			if(data.dnsmasq_user_instances) {
				output.dnsmasq_user_instances = [];
				if(data.dnsmasq_user_instances && data.dnsmasq_user_instances.length > 1) {
					for(let i of data.dnsmasq_user_instances) {
						if(i.nftables) {
							let name;
							i.nftables.forEach(e => {
								if(e.set) {
									name = e.set.name;
								};
							});
							output.dnsmasq_user_instances.push([ name, parseDnsmasqData(i) ]);
						};
					};
				};
			};
			// IPv6-зеркала dnsmasq-наборов (названия dnsmasq6/dnsmasq6_bypass/dnsmasq6_user_instances
			// добавляются бэкендом html-info при enable_ipv6=1). Список имён наборов в этих
			// блоках — d6 / d6.<instance> / bd6 / и т.п. Уже обрабатываются formatRuleDescription.
			if(data.dnsmasq6) {
				output.dnsmasq6 = parseDnsmasqData(data.dnsmasq6);
			};
			if(data.dnsmasq6_bypass) {
				output.dnsmasq6_bypass = parseDnsmasqData(data.dnsmasq6_bypass);
			};
			if(data.dnsmasq6_user_instances) {
				output.dnsmasq6_user_instances = [];
				if(data.dnsmasq6_user_instances && data.dnsmasq6_user_instances.length > 1) {
					for(let i of data.dnsmasq6_user_instances) {
						if(i.nftables) {
							let name;
							i.nftables.forEach(e => {
								if(e.set) {
									name = e.set.name;
								};
							});
							output.dnsmasq6_user_instances.push([ name, parseDnsmasqData(i) ]);
						};
					};
				};
			};
		};
		return output;
	},

	makeDnsmasqTable(ipDataArray, title, family) {
		let lines   = `<tr class="tr"><td class="td center">${_('No entries available...')}</td></tr>`;
		let ipTable = E('table', { 'id': 'ipTable', 'class': 'table' });

		// Заголовок колонки: "IP address" для IPv4, "IPv6 address" для IPv6
		let addr_label = (family === '6') ? _('IPv6 address') : _('IP address');

		ipDataArray.sort((a, b) => a[1] - b[1]);

		if(ipDataArray.length > 0) {
			lines = [];
			ipDataArray.forEach((e, i) => {
				if(e) {
					lines.push(
						`<tr class="tr"><td class="td left" data-title="${addr_label}">${e[0]}</td>` +
						`<td class="td left" data-title="${_('Timeout')}">${this.secToTimeString(e[1] | 0)}</td></tr>`
					);
				};
			});
			lines = lines.join('');

			ipTable.append(
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th left', 'style': 'width:33%' }, addr_label),
					E('th', { 'class': 'th left' }, _('Timeout')),
				])
			);
		};

		try {
			ipTable.insertAdjacentHTML('beforeend', lines);
		} catch(e) {
			if(e.name === 'SyntaxError') {
				ui.addNotification(null,
					E('p', {}, _('HTML/XML error') + ': ' + e.message), 'error');
			};
			throw e;
		};

		return E([
			E('h3', {}, title),
			E('div', { 'class': 'log-entries-count' },
				`${_('Entries')}: ${ipDataArray.length}`
			),
			ipTable,
		]);
	},

	pollInfo() {
		return fs.exec_direct(tools.execPath, [ 'html-info' ], 'json').catch(e => {
			ui.addNotification(null, E('p', _('Unable to execute or read contents')
				+ ': %s [ %s ]'.format(e.message, tools.execPath)
			));
			poll.stop();
		}).then(data => {
			if(!data) {
				return;
			};

			try {
				data = JSON.parse(data);
			} catch(e) {};

			if(data.status === 'enabled') {
				let date = document.getElementById('last_blacklist_update.date');

				if(data.last_blacklist_update.status) {
					if(date) {
						date.textContent = data.last_blacklist_update.date;
					};

					let ip   = document.getElementById('last_blacklist_update.ip');
					if(ip) {
						ip.textContent = data.last_blacklist_update.ip;
					};

					let cidr = document.getElementById('last_blacklist_update.cidr');
					if(cidr) {
						cidr.textContent = data.last_blacklist_update.cidr;
					};

					let fqdn = document.getElementById('last_blacklist_update.fqdn');
					if(fqdn) {
						fqdn.textContent = data.last_blacklist_update.fqdn;
					};
				} else {
					if(date) {
						date.textContent = _('No data');
					};
				};

				let nft_data = this.formatNftJson(data);

				if(nft_data.rules.length > 0) {
					for(let [set, bytes] of nft_data.rules) {
						let elem = document.getElementById('rules.' + set);
						if(elem) {
							elem.textContent = bytes;
						};
					};
				};

				let rdTableWrapper = document.getElementById('rdTableWrapper');
				if(rdTableWrapper) {
					rdTableWrapper.innerHTML = '';
					rdTableWrapper.append(this.makeDnsmasqTable(nft_data.dnsmasq, _('Dnsmasq')));
				};

				let rdsTableWrapper = document.getElementById('rdsTableWrapper');
				if(rdsTableWrapper) {
					rdsTableWrapper.innerHTML = '';
					for(let i of nft_data.dnsmasq_user_instances) {
						rdsTableWrapper.append(this.makeDnsmasqTable(i[1], _('Dnsmasq') + ' ' + i[0]));
					};
				};
				let rdbTableWrapper = document.getElementById('rdbTableWrapper');
				if(rdbTableWrapper) {
					rdbTableWrapper.innerHTML = '';
					rdbTableWrapper.append(this.makeDnsmasqTable(nft_data.dnsmasq_bypass, _('Dnsmasq bypass')));
				};

				// IPv6 таблицы dnsmasq (создаются в render только при enable_ipv6=1)
				let rd6TableWrapper = document.getElementById('rd6TableWrapper');
				if(rd6TableWrapper) {
					rd6TableWrapper.innerHTML = '';
					if(nft_data.dnsmasq6) {
						rd6TableWrapper.append(this.makeDnsmasqTable(nft_data.dnsmasq6, _('Dnsmasq (IPv6)'), '6'));
					};
				};

				let rds6TableWrapper = document.getElementById('rds6TableWrapper');
				if(rds6TableWrapper) {
					rds6TableWrapper.innerHTML = '';
					if(nft_data.dnsmasq6_user_instances) {
						for(let i of nft_data.dnsmasq6_user_instances) {
							rds6TableWrapper.append(this.makeDnsmasqTable(i[1], _('Dnsmasq (IPv6)') + ' ' + i[0], '6'));
						};
					};
				};
				let rdb6TableWrapper = document.getElementById('rdb6TableWrapper');
				if(rdb6TableWrapper) {
					rdb6TableWrapper.innerHTML = '';
					if(nft_data.dnsmasq6_bypass) {
						rdb6TableWrapper.append(this.makeDnsmasqTable(nft_data.dnsmasq6_bypass, _('Dnsmasq bypass (IPv6)'), '6'));
					};
				};
			} else {
				if(poll.active()) {
					poll.stop();
				};
			};
		});
	},

	formatRuleDescription(s) {
		// IPv4 наборы (оригинал): c, i, d, onion, bi, bd, fproxy, bllist_proxy, local_ip, allowed_ip
		// IPv6 наборы (новое):     c6, i6, d6, onion6, bi6, bd6, fproxy6, bllist_proxy6, local_ip6, allowed_ip6
		// Сначала проверяем IPv6-имена (c6|i6|d6|onion6...), потом IPv4.
		return (s.length >= 1) ? (
			s.replace(/^local_ip6\.?(.*)/, '$1 local IPv6 addresses')
				.replace(/^allowed_ip6\.?(.*)/, '$1 allowed IPv6 hosts')
				.replace(/^fproxy_local6\.?(.*)/, '$1 fproxy local IPv6')
				.replace(/^fproxy6\.?(.*)/, '$1 fproxy IPv6')
				.replace(/^bllist_proxy6\.?(.*)/, '$1 blacklist-proxy IPv6')
				.replace(/^c6\.?(.*)/, '$1 CIDR IPv6')
				.replace(/^i6\.?(.*)/, '$1 IP IPv6')
				.replace(/^d6\.?(.*)/, '$1 dnsmasq IPv6')
				.replace(/^onion6\.?(.*)/, '$1 onion IPv6')
				.replace(/^bi6/, 'bypass IP IPv6').replace(/^bd6/, 'bypass dnsmasq IPv6')
				.replace(/^c\.?(.*)/, '$1 CIDR').replace(/^i\.?(.*)/, '$1 IP')
				.replace(/^d\.?(.*)/, '$1 dnsmasq').replace(/^onion\.?(.*)/, '$1 onion')
				.replace(/^bi/, 'bypass IP').replace(/^bd/, 'bypass dnsmasq')
				.replace(/^local_ip\.?(.*)/, '$1 local IPv4 addresses')
				.replace(/^allowed_ip\.?(.*)/, '$1 allowed IPv4 hosts')
				.replace(/^fproxy_local\.?(.*)/, '$1 fproxy local IPv4')
				.replace(/^fproxy\.?(.*)/, '$1 fproxy IPv4')
				.replace(/^bllist_proxy\.?(.*)/, '$1 blacklist-proxy IPv4')
		) : '';
	},

	load() {
		return fs.exec_direct(tools.execPath, [ 'html-info' ], 'json').catch(e => {
			ui.addNotification(null, E('p', _('Unable to execute or read contents')
				+ ': %s [ %s ]'.format(e.message, tools.execPath)
			));
		})
	},

	render(data) {
		if(!data) {
			return;
		};

		try {
			data = JSON.parse(data);
		} catch(e) {};

		let update_status         = null,
			user_entries          = null,
			rules                 = null,
			dnsmasq               = null,
			dnsmasqUserInstances  = null,
			dnsmasqBypass         = null,
			// IPv6-таблицы dnsmasq (отображаются только при enable_ipv6=1)
			dnsmasq6              = null,
			dnsmasq6UserInstances = null,
			dnsmasq6Bypass        = null;

		if(data) {
			if(data.status === 'enabled') {
				update_status = E('table', { 'class': 'table' });

				if(data.last_blacklist_update.status) {
					update_status.append(
						E('tr', { 'class': 'tr' }, [
							E('td', { 'class': 'td left', 'style': 'width:33%' },
								_('Last blacklist update') + ':'),
							E('td', { 'class': 'td left',
										'id' : 'last_blacklist_update.date' },
								data.last_blacklist_update.date),
						]),
						E('tr', { 'class': 'tr' }, [
							E('td', { 'class': 'td left' }, 'CIDR:'),
							E('td', { 'class': 'td left',
										'id' : 'last_blacklist_update.cidr' },
								data.last_blacklist_update.cidr),
						]),
						E('tr', { 'class': 'tr' }, [
							E('td', { 'class': 'td left' }, 'IP:'),
							E('td', { 'class': 'td left',
										'id' : 'last_blacklist_update.ip' },
								data.last_blacklist_update.ip),
						]),
						E('tr', { 'class': 'tr' }, [
							E('td', { 'class': 'td left' }, 'FQDN:'),
							E('td', { 'class': 'td left',
										'id' : 'last_blacklist_update.fqdn' },
								data.last_blacklist_update.fqdn),
						])
					);
				} else {
					update_status.append(
						E('tr', { 'class': 'tr' }, [
							E('td', { 'class': 'td left', 'style': 'width:33%' },
								_('Last blacklist update') + ':'),
							E('td', { 'class': 'td left' }, _('No data')),
						])
					);
				};

				if(data.user_entries && data.user_entries.length > 0) {
					user_entries = E('table', { 'class': 'table' });
					for(let i of data.user_entries) {
						user_entries.append(
							E('tr', { 'class': 'tr' }, [
								E('td', { 'class': 'td left', 'style': 'word-wrap:break-word' },
									i.id.slice(0, 114) + (i.id.length > 115 ? '...' : '')),
								E('td', { 'class': 'td left' },
									`CIDR: ${i.cidr}, IP: ${i.ip}, FQDN: ${i.fqdn}`),
							])
						);
					};
				};

				let nft_data = this.formatNftJson(data);

				if(nft_data.rules) {
					let table_rules = E('table', { 'class': 'table' }, [
						E('tr', { 'class': 'tr table-titles' }, [
							E('th', { 'class': 'th left', 'style': 'width:33%' },
								_('Match-set')),
							E('th', { 'class': 'th left' }, _('Description')),
							E('th', { 'class': 'th left' }, _('Bytes')),
						]),
					]);

					for(let [set, bytes] of nft_data.rules) {
						if(!set) {
							continue;
						};
						table_rules.append(
							E('tr', { 'class': 'tr' }, [
								E('td',{
									'class'     : 'td left',
									'data-title': _('Match-set'),
								}, set),
								E('td', {
									'class'     : 'td left',
									'data-title': _('Description'),
								}, this.formatRuleDescription(set)),
								E('td', {
									'class'     : 'td left',
									'id'        : 'rules.' + set,
									'data-title': _('Bytes'),
								}, bytes),
							])
						);
					};

					rules = E([
						E('h3', {}, _('Nftables rules')),
						table_rules,
					]);
				};

				if(nft_data.dnsmasq) {
					let rdTableWrapper = E('div', {
						'id'   : 'rdTableWrapper',
						'style': 'width:100%',
					}, this.makeDnsmasqTable(nft_data.dnsmasq, _('Dnsmasq')));
					dnsmasq = rdTableWrapper;
				};

				if(nft_data.dnsmasq_user_instances) {
					let rdsTableWrapper = E('div', {
						'id'   : 'rdsTableWrapper',
						'style': 'width:100%',
					});

					for(let i of nft_data.dnsmasq_user_instances) {
						rdsTableWrapper.append(this.makeDnsmasqTable(i[1], _('Dnsmasq') + ' ' + i[0]));
					};

					if(nft_data.dnsmasq_user_instances.length > 0) {
						dnsmasqUserInstances = rdsTableWrapper;
					};
				};

				if(nft_data.dnsmasq_bypass) {
					let rdbTableWrapper = E('div', {
						'id'   : 'rdbTableWrapper',
						'style': 'width:100%',
					}, this.makeDnsmasqTable(nft_data.dnsmasq_bypass, _('Dnsmasq bypass')));
					dnsmasqBypass = rdbTableWrapper;
				};

				// IPv6-зеркала dnsmasq-таблиц (присутствуют только при enable_ipv6=1)
				if(nft_data.dnsmasq6) {
					let rd6TableWrapper = E('div', {
						'id'   : 'rd6TableWrapper',
						'style': 'width:100%',
					}, this.makeDnsmasqTable(nft_data.dnsmasq6, _('Dnsmasq (IPv6)'), '6'));
					dnsmasq6 = rd6TableWrapper;
				};

				if(nft_data.dnsmasq6_user_instances) {
					let rds6TableWrapper = E('div', {
						'id'   : 'rds6TableWrapper',
						'style': 'width:100%',
					});

					for(let i of nft_data.dnsmasq6_user_instances) {
						rds6TableWrapper.append(this.makeDnsmasqTable(i[1], _('Dnsmasq (IPv6)') + ' ' + i[0], '6'));
					};

					if(nft_data.dnsmasq6_user_instances.length > 0) {
						dnsmasq6UserInstances = rds6TableWrapper;
					};
				};

				if(nft_data.dnsmasq6_bypass) {
					let rdb6TableWrapper = E('div', {
						'id'   : 'rdb6TableWrapper',
						'style': 'width:100%',
					}, this.makeDnsmasqTable(nft_data.dnsmasq6_bypass, _('Dnsmasq bypass (IPv6)'), '6'));
					dnsmasq6Bypass = rdb6TableWrapper;
				};

				poll.add(L.bind(this.pollInfo, this), this.pollInterval);
			} else {
				update_status = E('em', {}, _('Status') + ' : ' + _('disabled'));
			};
		};

		let layout = [
			E('h2', { 'class': 'fade-in' },
				_('Ruantiblock') + ' - ' + _('Statistics')
			),
			E('div', { 'class': 'cbi-section-descr fade-in' }),
			E('div', { 'class': 'cbi-section fade-in' },
				E('div', { 'class': 'cbi-section-node' }, update_status)
			),
			E('div', { 'class': 'cbi-section fade-in' },
				E('div', { 'class': 'cbi-section-node' }, rules)
			),
		];

		if(user_entries) {
			layout.splice(3, 0,
				E('div', { 'class': 'cbi-section fade-in' }, [
					E('h3', {}, _('User entries')),
					E('div', { 'class': 'cbi-section-node' }, user_entries),
				])
			);
		}

		if(dnsmasqBypass) {
			layout.splice(5, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasqBypass)
				)
			);
		};

		if(dnsmasqUserInstances) {
			layout.splice(6, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasqUserInstances)
				)
			);
		};

		if(dnsmasq) {
			layout.splice(7, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasq)
				)
			);
		};

		// IPv6-таблицы dnsmasq (показываются только если html-info вернул v6-данные)
		if(dnsmasq6Bypass) {
			layout.splice(8, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasq6Bypass)
				)
			);
		};

		if(dnsmasq6UserInstances) {
			layout.splice(9, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasq6UserInstances)
				)
			);
		};

		if(dnsmasq6) {
			layout.splice(10, 0,
				E('div', { 'class': 'cbi-section fade-in' },
					E('div', { 'class': 'cbi-section-node' }, dnsmasq6)
				)
			);
		};

		return E(layout);
	},

	handleSave     : null,
	handleSaveApply: null,
	handleReset    : null,
});
