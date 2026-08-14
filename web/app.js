/* claude-egress-monitor —— 界面侧的应用逻辑。
 *
 * 三条自我约束：
 *
 * 1. **不发明数字。** 这里只渲染 /api/state 返回的字段。没有的值渲染成
 *    破折号，绝不用 0、"未知"或者上一轮的值顶上 —— 一个假的 0 会被
 *    读成"延迟 0 毫秒"。
 * 2. **不拼 HTML 字符串。** 所有节点用 el() 造，文本一律走 textContent。
 *    这个界面显示的是主机名、进程名、ASN 组织名，都是从系统里读来的
 *    外部输入，拼进 innerHTML 就是一个 XSS。
 * 3. **状态以服务端为准。** 开关点下去先发请求，再按响应回写 UI，
 *    而不是先改 UI 再假设请求会成功。
 *
 * 交互里凡是 atelier 已经用 data-* 提供的（路由、标签、折叠、排序、
 * 分段控件的选中态、明暗与语言切换）都不在这里重写，只在它之上挂效果。
 */
(function () {
  'use strict';

  var DASH = '—';
  var LATENCY_CEILING_MS = 1500;   // 延迟柱的量纲上限，和 HTML 里的刻度一致

  var KIND_TEXT = {
    'real':        { zh: '真实公网地址', en: 'real address' },
    'fake-ip':     { zh: 'fake-ip 占位', en: 'fake-ip placeholder' },
    'local-proxy': { zh: '本机代理（目的地不可见）', en: 'local proxy (destination hidden)' },
    'private':     { zh: '内网 / 回环', en: 'private / loopback' }
  };

  // 圆球里的两个字母。不能拿类别 slug 的前两个字母截 ——
  // content 和 control 都会截成 "CO"，两个不同类别长得一样。
  var CATEGORY_MARK = {
    'api': 'AP', 'auth': 'AU', 'control': 'CF', 'telemetry': 'TE',
    'update': 'UP', 'content': 'DO', 'mcp': 'MC'
  };

  var DNS_VERDICT = {
    'real':     { zh: '一致', en: 'consistent', chip: 'atl-chip--up' },
    'fake-ip':  { zh: 'fake-ip', en: 'fake-ip', chip: 'atl-chip--warn' },
    'mismatch': { zh: '被改写', en: 'rewritten', chip: 'atl-chip--warn' },
    'unknown':  { zh: '无法对账', en: 'unverified', chip: '' },
    'error':    { zh: '解析失败', en: 'resolve failed', chip: 'atl-chip--down' }
  };

  // ------------------------------------------------------------ 小工具

  function q(name) {
    return document.querySelector('[data-cem="' + name + '"]');
  }

  function lang() {
    return document.documentElement.getAttribute('data-lang') === 'en' ? 'en' : 'zh';
  }

  /** 造节点。attrs 里的 class / style / 其余属性都走 setAttribute。 */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] === null || attrs[k] === undefined) return;
        node.setAttribute(k, String(attrs[k]));
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      // 只有真正的 Node 才 appendChild，其余（字符串、数字）一律转成文本节点。
      // 早先这里只认字符串，于是传进一个数字就 appendChild(5) 抛 TypeError，
      // 整个 render 从那一行起全部不执行 —— 而外层的 .catch 把异常吞了，
      // 症状是"有几个面板永远是空的"，看不出任何报错。
      node.appendChild(child instanceof Node
        ? child
        : document.createTextNode(String(child)));
    });
    return node;
  }

  /** 双语文本节点：两个 span，由 CSS 按 data-lang 决定显示哪个。 */
  function bi(zh, en) {
    var wrap = document.createDocumentFragment();
    wrap.appendChild(el('span', { class: 'lang-zh' }, [zh]));
    wrap.appendChild(el('span', { class: 'lang-en' }, [en || zh]));
    return wrap;
  }

  function biSpan(zh, en, cls) {
    var s = el('span', cls ? { class: cls } : null, []);
    s.appendChild(bi(zh, en));
    return s;
  }

  function txt(value) {
    return (value === null || value === undefined || value === '') ? DASH : String(value);
  }

  function ms(value) {
    if (value === null || value === undefined) return DASH;
    return Math.round(value) + ' ms';
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function fmtTime(ts) {
    if (!ts) return DASH;
    var d = new Date(ts * 1000);
    function p(n) { return n < 10 ? '0' + n : String(n); }
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function fmtDate(ts) {
    if (!ts) return DASH;
    var d = new Date(ts * 1000);
    return (d.getMonth() + 1) + '/' + d.getDate();
  }

  /** 地区显示成 "SG · 新加坡"：两种语言的读者都能读，不需要切换。 */
  function region(code, label) {
    if (!code) return DASH;
    if (!label || label === code) return code;
    return code + ' · ' + label;
  }

  // ------------------------------------------------------------ 接口

  function post(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    });
  }

  // ------------------------------------------------------------ 渲染：入口卡

  // p50 / p95 在界面上出现很多次，解释统一放这里当 tooltip。
  var P50_HINT = '中位数：把所有测量排序后取正中间那个。一半请求比它快，'
    + '一半比它慢。用它而不是平均值，因为一次抖动就能把平均值拉飞。';
  var P95_HINT = '第 95 百分位：只有 5% 的请求比它更慢，代表「最糟的日常情况」。'
    + 'p50 低但 p95 高的链路用起来比两者都中等的更让人烦躁。';

  var LEVEL_TONE = {
    'identical': 'atl-chip--up',
    'dual-stack': 'atl-chip',
    'same-network': 'atl-chip',
    'multi-network': 'atl-chip--warn',
    'multi-country': 'atl-chip--down'
  };

  function surfaceCard(card) {
    var body = [];

    var head = el('div', { class: 'surface-card__head' }, [
      el('span', { class: 'atl-orb' }, [orbGlyph()]),
      el('span', {}, [
        el('span', { class: 'surface-card__name' }, [card.label]),
        el('span', { class: 'surface-card__route' }, [
          card.proxy
            ? (lang() === 'en' ? 'via proxy ' : '经代理 ') + card.proxy
            : (lang() === 'en' ? 'direct' : '直连')
        ])
      ])
    ]);
    // 进程在不在跑。这一格是为了让读者知道这张卡是推算还是有对应的实体在跑 ——
    // 桌面端关着却显示出口，是这个界面最容易被误读的地方。
    if (card.running) {
      head.appendChild(biSpan('进程运行中', 'running',
        'atl-chip atl-chip--up'));
    } else {
      head.appendChild(el('span', {
        class: 'atl-chip',
        title: (lang() === 'en'
          ? 'This entry point is not running. The exit below is what it WOULD use, probed via its proxy config.'
          : '这个入口当前没有进程在跑。下面的出口是「按它的代理配置探测出来的会怎样」，不是观测到的真实流量。')
      }, [lang() === 'en' ? 'not running' : '未运行']));
    }
    head.lastChild.setAttribute('style', 'margin-left:auto;');
    body.push(head);

    var geo = el('div', { class: 'surface-card__geo' }, [
      el('span', { class: 'surface-card__country' }, [
        txt(card.country_label || card.country)
      ])
    ]);
    if (card.colo) {
      // colo 是 IATA 机场三字码，标的是**哪个 Cloudflare 边缘机房接待了
      // 这次请求**，不是"你的出口在哪"。anycast 就近路由所以通常挨得很近，
      // 但不是一回事 —— 不解释的话读者会把它当成出口位置。
      geo.appendChild(el('span', {
        class: 'atl-chip',
        title: (lang() === 'en'
          ? 'Cloudflare edge datacenter (IATA airport code) that served this request — close to your exit, but not the same thing as where your exit is.'
          : 'Cloudflare 边缘机房，用 IATA 机场三字码命名（NRT 东京成田 / SIN 新加坡樟宜 / LAX 洛杉矶…）。它标的是「哪个机房接待了这次请求」，通常离你的出口很近，但不等于出口位置本身。')
      }, ['colo ' + card.colo]));
    }
    if (card.family) geo.appendChild(el('span', { class: 'atl-chip' }, [card.family]));
    if (card.restricted) {
      geo.appendChild(biSpan('受限地区', 'restricted', 'atl-chip atl-chip--down'));
    }
    // 机房 / 家宽 —— 这是风控权重差别最大的一个属性。
    // 后面必须跟置信度：「厂商官方地址段命中」和「组织名里有 cloud 这个词」
    // 都会显示成"机房"，但可信度差着两个数量级。不标出来读者没法判断。
    if (card.kind && card.kind !== 'unknown') {
      geo.appendChild(el('span', {
        class: 'atl-chip' + (card.kind === 'datacenter' ? ' atl-chip--warn' : ''),
        title: card.kind_evidence || ''
      }, [card.kind_label || card.kind]));
      if (card.confidence_label) {
        geo.appendChild(el('span', {
          class: 'atl-chip' + (card.confidence === 'confirmed' ? ' atl-chip--up' : ''),
          title: card.kind_evidence || ''
        }, [card.confidence_label]));
      }
    }
    if (card.proxy_flagged) {
      geo.appendChild(biSpan('已知代理库', 'listed proxy', 'atl-chip atl-chip--down'));
    }
    body.push(geo);

    body.push(el('span', { class: 'surface-card__ip' }, [txt(card.egress_ip)]));

    // 城市 / 运营商：国家相同、地址不同的时候，这两行是唯一能把
    // 两个出口区分开的人类可读信息。
    var g = card.geo || {};
    var who = [g.where, card.org || g.short_org, card.asn].filter(Boolean).join(' · ');
    if (who) {
      body.push(el('span', { class: 'atl-muted', style: 'font-size:12.5px;' }, [who]));
    }
    if (g.rdns) {
      body.push(el('span', {
        class: 'atl-mono atl-muted', style: 'font-size:11px; overflow-wrap:anywhere;'
      }, [g.rdns]));
    }

    // 一致性级别 —— 「国家相同」不等于「出口相同」，所以这里分五档而不是两档
    if (card.level) {
      var tone = LEVEL_TONE[card.level] || 'atl-chip';
      var levelRow = el('div', { class: 'atl-row', style: 'flex-wrap:wrap;' }, [
        el('span', { class: tone }, [card.level_label || card.level]),
        el('span', { class: 'atl-muted', style: 'font-size:12px;' }, [
          (card.domains || 0) + (lang() === 'en' ? ' domains' : ' 个域名') +
          ' · ' + (card.addresses || []).length +
          (lang() === 'en' ? ' address(es)' : ' 个出口地址')
        ])
      ]);
      body.push(levelRow);
    }

    // 多于一个出口地址时，把每个地址和它覆盖的域名都列出来
    if ((card.addresses || []).length > 1) {
      var list = el('div', { class: 'exit-list', style: 'margin-top:6px;' }, []);
      card.addresses.forEach(function (a) {
        var ag = a.geo || {};
        list.appendChild(el('div', { class: 'exit-row' }, [
          el('span', { class: 'exit-row__ip' }, [a.ip]),
          el('span', { class: 'atl-chip' }, [a.family]),
          el('span', { class: 'exit-row__meta' }, [
            [ag.where || a.country_label || a.country,
             a.org || ag.short_org, a.asn, a.colo].filter(Boolean).join(' · ') +
            ' — ' + a.host_count + (lang() === 'en' ? ' domains' : ' 个域名')
          ])
        ]));
      });
      body.push(list);
    }

    if (card.kind_meaning) {
      body.push(el('span', {
        class: 'atl-muted', style: 'font-size:12px; line-height:1.6;'
      }, [card.kind_meaning]));
    }

    if (card.level_meaning) {
      body.push(el('span', {
        class: 'atl-muted', style: 'font-size:12px; line-height:1.6;'
      }, [card.level_meaning]));
    }

    return el('div', { class: 'atl-card' }, [el('div', { class: 'surface-card' }, body)]);
  }

  function orbGlyph() {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.9');
    svg.setAttribute('stroke-linecap', 'round');
    var a = document.createElementNS(ns, 'circle');
    a.setAttribute('cx', '12'); a.setAttribute('cy', '12'); a.setAttribute('r', '8.4');
    var b = document.createElementNS(ns, 'path');
    b.setAttribute('d', 'M3.6 12h16.8M12 3.6c2.5 2.4 2.5 14.4 0 16.8-2.5-2.4-2.5-14.4 0-16.8z');
    svg.appendChild(a); svg.appendChild(b);
    return svg;
  }

  function renderSurfaces(state) {
    var host = q('surface-grid');
    if (!host) return;
    var cards = (state.surfaces || []).filter(function (c) { return c.egress_ip; });
    if (!cards.length) return;              // 保留 HTML 里的空状态
    clear(host);
    cards.forEach(function (c) { host.appendChild(surfaceCard(c)); });
  }

  // ------------------------------------------------------------ 渲染：结论

  function renderNotes(state) {
    var host = q('notes-list');
    var count = q('notes-count');
    var notes = state.notes || [];
    if (count) count.textContent = String(notes.length);
    if (!host || !notes.length) return;
    clear(host);
    notes.forEach(function (note) {
      host.appendChild(el('div', { class: 'note-item' }, [
        el('span', { class: 'note-item__dot' }, []),
        el('span', { class: 'note-item__text' }, [note])
      ]));
    });
  }

  // ------------------------------------------------------------ 渲染：遥测

  function renderTelemetry(state) {
    var host = q('telemetry-list');
    if (!host) return;
    var rows = (state.traces || []).filter(function (t) {
      return t.category === 'telemetry' && t.path === 'cli';
    });
    if (!rows.length) return;
    clear(host);
    rows.forEach(function (t) {
      var total = t.timing && t.timing.total_ms;
      var pct = total === null || total === undefined
        ? 0
        : Math.max(2, Math.min(100, (total / LATENCY_CEILING_MS) * 100));
      var meter = el('span', { class: 'atl-meter', style: 'flex:1;' }, [
        el('span', {
          class: 'atl-meter__fill',
          style: 'width:' + pct.toFixed(1) + '%'
        }, [])
      ]);
      var reach = t.ok
        ? biSpan('可达', 'reachable', 'atl-chip atl-chip--up')
        : biSpan('不可达', 'unreachable', 'atl-chip atl-chip--down');
      host.appendChild(el('div', { class: 'tele-row' }, [
        el('span', { class: 'tele-row__host' }, [t.target]),
        el('span', { class: 'tele-row__bottom' }, [
          el('span', { class: 'tele-row__meta' }, [ms(total)]),
          meter,
          reach
        ])
      ]));
    });
  }

  // ------------------------------------------------------------ 渲染：路径

  function renderPaths(state) {
    var host = q('paths-list');
    if (!host) return;
    var paths = state.paths || [];
    if (!paths.length) return;
    clear(host);
    paths.forEach(function (p) {
      host.appendChild(el('div', { class: 'note-item' }, [
        el('span', { class: 'note-item__dot' }, []),
        el('span', { class: 'note-item__text' }, [
          el('strong', {}, [p.label + (p.proxy ? ' · ' + p.proxy : '')]),
          el('br', {}, []),
          el('span', { class: 'atl-muted' }, [p.detail])
        ])
      ]));
    });
  }

  // ------------------------------------------------------------ 渲染：变更

  function renderChanges(state) {
    var host = q('changes-list');
    if (!host) return;
    var rows = state.changes || [];
    if (!rows.length) return;
    clear(host);
    rows.slice(0, 8).forEach(function (c) {
      var head = c.first
        ? biSpan('首次记录', 'first reading')
        : biSpan('出口变更', 'exit changed');
      host.appendChild(el('div', { class: 'atl-timeline__row' }, [
        el('span', { class: 'atl-timeline__time' }, [
          fmtTime(c.ts),
          el('span', { class: 'atl-timeline__date' }, [fmtDate(c.ts)])
        ]),
        el('span', { class: 'atl-timeline__spine' }, [
          el('span', { class: 'atl-timeline__dot' }, [])
        ]),
        el('span', { class: 'atl-timeline__body' }, [
          el('strong', { style: 'font-size:13.5px;' }, [
            c.path_label + ' · ' + region(c.country, c.country_label)
          ]),
          el('br', {}, []),
          el('span', { class: 'atl-mono atl-muted', style: 'font-size:11.5px;' }, [
            txt(c.egress_ip)
          ]),
          el('br', {}, []),
          head
        ])
      ]));
    });
  }

  // ------------------------------------------------------------ 渲染：表格

  function renderDomains(state) {
    var body = q('domains-body');
    if (!body) return;
    var rows = state.traces || [];
    if (!rows.length) return;
    clear(body);
    rows.forEach(function (t) {
      var total = t.timing && t.timing.total_ms;
      var tr = el('tr', {}, [
        el('td', { 'data-col': 'host', style: 'font-weight:700;' }, [
          el('span', { class: 'wrap-mono' }, [t.target])
        ]),
        el('td', { 'data-col': 'path' }, [t.path]),
        el('td', {}, [el('span', { class: 'wrap-mono' }, [txt(t.egress_ip)])]),
        el('td', { 'data-col': 'region' }, [region(t.country, t.country_label)]),
        el('td', { class: 'atl-muted' }, [txt(t.colo)]),
        el('td', {
          'data-col': 'total',
          'data-value': (total === null || total === undefined) ? '999999' : String(total)
        }, [
          el('span', { class: 'atl-row' }, [
            el('span', { class: 'atl-meter', style: 'flex:1;' }, [
              el('span', {
                class: 'atl-meter__fill',
                style: 'width:' + (total
                  ? Math.max(2, Math.min(100, (total / LATENCY_CEILING_MS) * 100)).toFixed(1)
                  : 0) + '%'
              }, [])
            ]),
            el('span', { class: 'atl-mono', style: 'font-size:12px;' }, [
              total ? Math.round(total) : DASH
            ])
          ])
        ])
      ]);
      if (!t.ok && t.error) {
        tr.setAttribute('title', t.error);
      }
      body.appendChild(tr);
    });
  }

  function renderConnections(state) {
    var body = q('conns-body');
    var badge = q('badge-conns');
    var rows = state.connections || [];
    if (badge) badge.textContent = String(rows.length);
    if (!body || !rows.length) return;
    clear(body);
    rows.forEach(function (c) {
      var kind = KIND_TEXT[c.kind] || { zh: c.kind, en: c.kind };
      var owner = DASH;
      if (c.host) owner = c.host;
      else if (c.asn && c.asn.org) owner = c.asn.org;
      var ownerCell = el('td', {}, [
        el('span', { class: 'wrap-mono' }, [owner])
      ]);
      if (c.asn && (c.asn.asn || c.asn.country)) {
        ownerCell.appendChild(el('span', {
          class: 'atl-muted', style: 'display:block; font-size:11.5px;'
        }, [
          [c.asn.asn, region(c.asn.country, c.asn.country_label),
           c.asn.city, c.asn.anycast ? 'anycast' : null]
            .filter(Boolean).join(' · ')
        ]));
      }
      body.appendChild(el('tr', {}, [
        el('td', {}, [c.surface_label || c.surface]),
        el('td', {}, [el('span', { class: 'wrap-mono' }, [c.remote])]),
        el('td', {}, [biSpan(kind.zh, kind.en, 'atl-chip')]),
        ownerCell,
        el('td', { class: 'atl-table__num' }, [String(c.sockets)])
      ]));
    });
  }

  function renderDns(state) {
    var body = q('dns-body');
    if (!body) return;
    var rows = state.resolves || [];
    if (!rows.length) return;
    clear(body);
    rows.forEach(function (r) {
      var verdict = DNS_VERDICT[r.kind] || { zh: r.kind, en: r.kind, chip: '' };
      var chipCls = 'atl-chip' + (verdict.chip ? ' ' + verdict.chip : '');
      var tr = el('tr', {}, [
        el('td', { style: 'font-weight:700;' }, [
          el('span', { class: 'wrap-mono' }, [r.host])
        ]),
        el('td', {}, [el('span', { class: 'wrap-mono' }, [
          (r.system || []).join(', ') || DASH
        ])]),
        el('td', {}, [el('span', { class: 'wrap-mono' }, [
          (r.doh || []).join(', ') || DASH
        ])]),
        el('td', { class: 'atl-muted' }, [
          el('span', { class: 'wrap-mono' }, [txt(r.resolver)])
        ]),
        el('td', {}, [biSpan(verdict.zh, verdict.en, chipCls)])
      ]);
      if (r.note) tr.setAttribute('title', r.note);
      body.appendChild(tr);
    });
  }

  // ------------------------------------------------------------ 渲染：延迟

  function renderLatency(state) {
    var rows = (state.latency || []).filter(function (r) {
      return r.category === 'api';
    });
    var bars = q('latency-bars');
    if (bars && rows.length) {
      clear(bars);
      rows.slice(0, 12).forEach(function (r) {
        var pct = r.p50 === null || r.p50 === undefined
          ? 0
          : Math.max(1, Math.min(100, (r.p50 / LATENCY_CEILING_MS) * 100));
        // 刻度必须短：8 根柱子挤在一张卡里，写成 "platform/desktop"
        // 最后一根会被卡片边缘裁掉。完整信息在 title 里，路径用一个字母。
        var short = r.host.split('.')[0];
        var mark = r.path === 'cli' ? 'C' : (r.path === 'desktop' ? 'D'
                                            : r.path.slice(0, 1).toUpperCase());
        bars.appendChild(el('div', { class: 'atl-bars__col' }, [
          el('div', { class: 'atl-bars__stack' }, [
            el('span', {
              class: 'atl-bars__fill',
              style: 'height:' + pct.toFixed(1) + '%',
              title: r.host + ' · ' + r.path_label + ' · p50 ' + ms(r.p50)
            }, [])
          ]),
          el('span', { class: 'atl-bars__tick' }, [short + '·' + mark])
        ]));
      });
    }

    var body = q('latency-body');
    if (body && (state.latency || []).length) {
      clear(body);
      state.latency.forEach(function (r) {
        body.appendChild(el('tr', {}, [
          el('td', { style: 'font-weight:700;' }, [
            el('span', { class: 'wrap-mono' }, [r.host])
          ]),
          el('td', {}, [r.path_label]),
          el('td', { class: 'atl-table__num' }, [String(r.n)]),
          el('td', { class: 'atl-table__num', title: P50_HINT }, [ms(r.p50)]),
          el('td', { class: 'atl-table__num', title: P95_HINT }, [ms(r.p95)]),
          el('td', { class: 'atl-table__num' }, [ms(r.min)]),
          el('td', { class: 'atl-table__num' }, [ms(r.max)])
        ]));
      });
    }

    var phases = q('phase-list');
    var one = (state.traces || []).filter(function (t) {
      return t.category === 'api' && t.ok && t.timing && t.timing.total_ms;
    })[0];
    if (phases && one) {
      clear(phases);
      phases.appendChild(el('p', {
        class: 'atl-muted', style: 'margin:0 0 var(--space-5); font-size:12.5px;'
      }, [one.target + ' · ' + one.path]));
      [['DNS', one.timing.dns_ms], ['TCP', one.timing.tcp_ms],
       ['TLS', one.timing.tls_ms],
       [lang() === 'en' ? 'first byte' : '首字节', one.timing.ttfb_ms]
      ].forEach(function (pair) {
        var value = pair[1];
        var pct = value === null || value === undefined
          ? 0
          : Math.max(2, Math.min(100, (value / one.timing.total_ms) * 100));
        phases.appendChild(el('div', { class: 'phase-row' }, [
          el('span', {}, [
            el('span', { class: 'atl-kpi__label' }, [pair[0]]),
            el('span', {
              style: 'font-weight:800; font-size:17px; ' +
                     'font-variant-numeric:tabular-nums; display:block;'
            }, [ms(value)])
          ]),
          el('span', { class: 'atl-hbar' }, [
            el('span', {
              class: 'atl-hbar__fill', style: 'width:' + pct.toFixed(1) + '%'
            }, []),
            el('span', { class: 'atl-hbar__value' }, [pct.toFixed(0) + '%'])
          ])
        ]));
      });
    }
  }

  // ------------------------------------------------------------ 渲染：清单

  function renderInventory(state) {
    var host = q('inventory-list');
    var version = q('inv-version');
    var eps = state.endpoints || [];
    if (version && state.meta && state.meta.cli_sampled) {
      version.textContent = 'CLI ' + state.meta.cli_sampled;
    }
    if (!host || !eps.length || host.getAttribute('data-filled') === '1') return;
    clear(host);

    var groups = {};
    var order = [];
    eps.forEach(function (e) {
      if (!groups[e.category]) { groups[e.category] = []; order.push(e.category); }
      groups[e.category].push(e);
    });

    order.forEach(function (cat) {
      host.appendChild(el('h3', {
        class: 'atl-navgroup__label',
        style: 'margin:var(--space-5) 0 var(--space-3);'
      }, [groups[cat][0].category_label]));
      var grid = el('div', { class: 'atl-grid atl-grid--2' }, []);
      groups[cat].forEach(function (e) {
        var tags = el('span', { class: 'inv-card__tags' }, []);
        e.surfaces.forEach(function (s) {
          tags.appendChild(el('span', { class: 'atl-chip' }, [s]));
        });
        e.evidence.forEach(function (ev) {
          tags.appendChild(el('span', { class: 'atl-chip atl-chip--accent' }, [ev]));
        });
        if (e.probe !== 'cf-trace') {
          tags.appendChild(biSpan('只能量延迟', 'latency only', 'atl-chip atl-chip--warn'));
        }
        var text = el('span', { class: 'inv-card__text' }, [
          el('span', { class: 'inv-card__host' }, [e.host]),
          el('span', { class: 'inv-card__why' }, [e.purpose]),
          tags
        ]);
        if (e.note) {
          text.appendChild(el('span', {
            class: 'inv-card__why', style: 'margin-top:6px;'
          }, [e.note]));
        }
        grid.appendChild(el('div', {
          class: 'atl-card atl-card--tight atl-card--solid inv-card'
        }, [
          el('span', { class: 'atl-orb atl-orb--soft atl-orb--sm' }, [
            CATEGORY_MARK[e.category] || e.category.slice(0, 2).toUpperCase()
          ]),
          text
        ]));
      });
      host.appendChild(grid);
    });
    host.setAttribute('data-filled', '1');
  }

  // ------------------------------------------------------ 渲染：诊断

  function sevDot(severity, label) {
    return el('span', { class: 'sev sev--' + severity }, [
      el('span', { class: 'sev__dot' }, []),
      el('span', { style: 'font-size:11px; font-weight:700; letter-spacing:0.08em;' },
         [label || severity])
    ]);
  }

  function renderFindings(state) {
    var host = q('findings-list');
    var badge = q('badge-findings');
    var chips = q('sev-chips');
    var rows = state.findings || [];
    var sev = state.severity || {};

    // 徽标只数需要动手的（必须处理 + 该修）。把"检查通过"也算进去，
    // 徽标会永远是个大数字，读者就不再看它了。
    var actionable = (sev.critical || 0) + (sev.warn || 0);
    if (badge) badge.textContent = String(actionable);

    if (chips) {
      clear(chips);
      [['critical', '必须处理', 'must fix'], ['warn', '该修', 'should fix'],
       ['info', '知道即可', 'FYI'], ['ok', '通过', 'passing']
      ].forEach(function (t) {
        if (!sev[t[0]]) return;
        chips.appendChild(el('span', { class: 'sev sev--' + t[0] }, [
          el('span', { class: 'sev__dot' }, []),
          el('span', { style: 'font-size:12px;' }, [
            (lang() === 'en' ? t[2] : t[1]) + ' ' + sev[t[0]]
          ])
        ]));
      });
    }

    if (!host || !rows.length) return;
    clear(host);
    rows.forEach(function (f) {
      var grid = el('div', { class: 'finding__grid' }, [
        el('span', { class: 'finding__key' }, [lang() === 'en' ? 'evidence' : '判据']),
        el('span', { class: 'finding__val atl-mono', style: 'font-size:12px;' },
           [f.evidence || DASH]),
        el('span', { class: 'finding__key' }, [lang() === 'en' ? 'cause' : '成因']),
        el('span', { class: 'finding__val' }, [f.cause || DASH]),
        el('span', { class: 'finding__key' }, [lang() === 'en' ? 'next' : '下一步']),
        el('span', { class: 'finding__val' }, [
          el('span', { class: 'finding__fix' }, [f.fix || DASH])
        ])
      ]);
      if (f.docs) {
        grid.appendChild(el('span', { class: 'finding__key' }, ['docs']));
        grid.appendChild(el('span', { class: 'finding__val atl-mono', style: 'font-size:12px;' },
                             [f.docs]));
      }
      host.appendChild(el('div', { class: 'finding' }, [
        el('div', { class: 'finding__head' }, [
          sevDot(f.severity, f.severity_label),
          el('span', { class: 'finding__title' }, [f.title])
        ]),
        grid
      ]));
    });
  }

  function renderChecks(state) {
    var host = q('checks-list');
    var rows = state.checks || [];
    if (!host || !rows.length) return;
    clear(host);
    rows.forEach(function (c) {
      host.appendChild(el('div', { class: 'finding', style: 'padding:var(--space-4) 0;' }, [
        el('div', { class: 'finding__head' }, [
          sevDot(c.severity, c.severity_label),
          el('span', { style: 'font-size:14px; font-weight:700;' }, [c.label]),
          el('span', { class: 'atl-mono atl-muted', style: 'font-size:11.5px; margin-left:auto;' },
             [txt(c.value)])
        ]),
        el('p', { class: 'atl-muted', style: 'margin:8px 0 0; font-size:12.5px; line-height:1.66;' },
           [c.detail || ''])
      ]));
    });
  }

  function renderStability(state) {
    var body = q('stability-body');
    var rows = state.stability || [];
    if (!body || !rows.length) return;
    clear(body);
    rows.forEach(function (r) {
      var verdict = r.country_changes
        ? biSpan('跨国漂移', 'cross-country drift', 'atl-chip atl-chip--down')
        : (r.network_changes
            ? biSpan('换过网络', 'network changed', 'atl-chip atl-chip--warn')
            : (r.ip_changes
                ? biSpan('同网换址', 'address changed', 'atl-chip')
                : biSpan('稳定', 'stable', 'atl-chip atl-chip--up')));
      body.appendChild(el('tr', {}, [
        el('td', { style: 'font-weight:700;' }, [r.path_label]),
        el('td', { class: 'atl-table__num' }, [r.rounds]),
        el('td', { class: 'atl-table__num' }, [r.ips.length]),
        el('td', { class: 'atl-table__num' }, [r.networks.length]),
        el('td', { class: 'atl-table__num' }, [r.ip_changes]),
        el('td', { class: 'atl-table__num' }, [r.country_changes]),
        el('td', {}, [verdict])
      ]));
    });
  }

  // ------------------------------------------------------ 图表：环图

  // 三个强调色 + 一个中性。超过就并成"其余" —— 环图切片多于 4 片
  // 就只能靠图例才读得懂，那说明它已经不工作了。
  var SLICE_COLORS = ['var(--atl-rose)', 'var(--atl-coral)', 'var(--atl-amber)',
                      'var(--atl-line-strong)'];
  var SVG_NS = 'http://www.w3.org/2000/svg';

  function donut(items, unitZh, unitEn) {
    var total = items.reduce(function (a, b) { return a + b.count; }, 0);
    if (!total) return null;

    var top = items.slice(0, 3);
    var rest = items.slice(3);
    if (rest.length) {
      top = top.concat([{
        key: lang() === 'en' ? 'rest' : '其余',
        count: rest.reduce(function (a, b) { return a + b.count; }, 0)
      }]);
    }

    var R = 46, C = 2 * Math.PI * R;
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 132 132');
    svg.setAttribute('width', '132');
    svg.setAttribute('height', '132');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label',
      top.map(function (t) { return t.key + ' ' + t.count; }).join(', '));

    var track = document.createElementNS(SVG_NS, 'circle');
    track.setAttribute('cx', '66'); track.setAttribute('cy', '66');
    track.setAttribute('r', String(R)); track.setAttribute('fill', 'none');
    track.setAttribute('stroke', 'var(--atl-track)');
    track.setAttribute('stroke-width', '15');
    svg.appendChild(track);

    var offset = 0;
    top.forEach(function (item, i) {
      var arc = C * (item.count / total);
      var seg = document.createElementNS(SVG_NS, 'circle');
      seg.setAttribute('cx', '66'); seg.setAttribute('cy', '66');
      seg.setAttribute('r', String(R)); seg.setAttribute('fill', 'none');
      seg.setAttribute('stroke', SLICE_COLORS[i]);
      seg.setAttribute('stroke-width', '15');
      seg.setAttribute('stroke-dasharray', arc.toFixed(2) + ' ' + (C - arc).toFixed(2));
      seg.setAttribute('stroke-dashoffset', String(-offset.toFixed(2)));
      seg.setAttribute('transform', 'rotate(-90 66 66)');
      svg.appendChild(seg);
      offset += arc;
    });

    var legend = el('div', { class: 'donut__legend' }, []);
    top.forEach(function (item, i) {
      legend.appendChild(el('div', { class: 'donut__row' }, [
        el('span', { class: 'donut__swatch', style: 'background:' + SLICE_COLORS[i] }, []),
        el('span', { class: 'donut__name' }, [item.label || item.key]),
        el('span', { class: 'donut__num' }, [
          Math.round(item.count * 100 / total) + '%'
        ])
      ]));
    });

    return el('div', { class: 'donut' }, [
      el('div', { class: 'donut__figure' }, [
        svg,
        el('div', { class: 'donut__center' }, [
          el('span', { class: 'donut__total' }, [total]),
          el('span', { class: 'donut__unit' }, [lang() === 'en' ? unitEn : unitZh])
        ])
      ]),
      legend
    ]);
  }

  // ------------------------------------------------------ 历史看板

  var pickedDays = [];
  var rangeCache = null;

  function fmtBytes(n) {
    if (!n) return '0 B';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function renderHistory(state) {
    var hist = state.history || {};
    var grid = q('day-grid');
    var badge = q('badge-days');
    var total = q('history-total');
    var days = hist.days || [];

    if (badge) badge.textContent = String(days.length);
    if (total) {
      total.textContent = days.length
        ? days.length + (lang() === 'en' ? ' days · ' : ' 天 · ') + fmtBytes(hist.total_bytes)
        : (lang() === 'en' ? 'no archive' : '暂无归档');
    }
    if (!grid || !days.length) return;

    clear(grid);
    days.forEach(function (d) {
      var maxP50 = 1500;
      var pct = d.p50 ? Math.max(3, Math.min(100, d.p50 / maxP50 * 100)) : 0;
      var card = el('button', {
        type: 'button',
        class: 'day-card' + (pickedDays.indexOf(d.day) >= 0 ? ' is-picked' : ''),
        'data-day': d.day,
        'aria-pressed': pickedDays.indexOf(d.day) >= 0 ? 'true' : 'false'
      }, [
        el('span', { class: 'day-card__day' }, [d.day]),
        el('span', { class: 'day-card__meta' }, [
          d.rounds + (lang() === 'en' ? ' rounds · ' : ' 轮 · ') +
          d.hours_covered + (lang() === 'en' ? 'h covered' : ' 小时覆盖')
        ]),
        el('span', { class: 'day-card__meta' }, [
          (lang() === 'en' ? 'p50 ' : 'p50 ') + (d.p50 ? Math.round(d.p50) + ' ms' : DASH) +
          ' · ' + fmtBytes(d.size_bytes)
        ]),
        el('span', { class: 'day-card__bar atl-meter' }, [
          el('span', { class: 'atl-meter__fill', style: 'width:' + pct.toFixed(1) + '%' }, [])
        ])
      ]);
      if (d.changes) {
        card.appendChild(el('span', {
          class: 'day-card__meta'
        }, [(lang() === 'en' ? 'exit changes ' : '出口变更 ') + d.changes]));
      }
      grid.appendChild(card);
    });
    updateDaysHint();
  }

  function updateDaysHint() {
    var hint = q('days-hint');
    if (!hint) return;
    clear(hint);
    hint.appendChild(document.createTextNode(
      pickedDays.length
        ? (lang() === 'en' ? 'selected: ' : '已选 ') + pickedDays.length +
          (lang() === 'en' ? ' day(s)' : ' 天')
        : (lang() === 'en' ? 'click a day card to select' : '点日期卡选中')
    ));
  }

  function renderRange(payload) {
    rangeCache = payload;
    var box = q('range-kpis');
    var combined = (payload && payload.combined) || null;
    if (box) box.hidden = !combined;
    if (!combined) return;

    var setNum = function (name, value) {
      var node = q(name);
      if (node) node.textContent = (value === null || value === undefined) ? DASH : String(value);
    };
    setNum('range-rounds', combined.rounds);
    setNum('range-changes', combined.changes);
    setNum('range-cc', combined.country_changes);

    var cd = q('country-donut');
    if (cd) {
      var chart = donut((combined.countries || []).map(function (c) {
        return { key: c.key, label: c.key, count: c.count };
      }), '次观测', 'readings');
      if (chart) { clear(cd); cd.appendChild(chart); }
    }

    var nd = q('network-donut');
    if (nd) {
      var chart2 = donut((combined.networks || []).map(function (n) {
        return { key: n.key, label: (n.org || n.key), count: n.count };
      }), '次观测', 'readings');
      if (chart2) { clear(nd); nd.appendChild(chart2); }
    }

    var body = q('addresses-body');
    if (body && (combined.addresses || []).length) {
      clear(body);
      combined.addresses.forEach(function (a) {
        body.appendChild(el('tr', {}, [
          el('td', {}, [el('span', { class: 'wrap-mono' }, [a.ip])]),
          el('td', {}, [el('span', { class: 'atl-chip' }, [a.family || DASH])]),
          el('td', {}, [[a.city, a.cc].filter(Boolean).join(' · ') || DASH]),
          el('td', {}, [[a.org, a.asn].filter(Boolean).join(' · ') || DASH]),
          el('td', {}, [
            el('span', { class: 'atl-row' }, [
              el('span', { class: 'atl-meter', style: 'flex:1;' }, [
                el('span', { class: 'atl-meter__fill', style: 'width:' + a.share + '%' }, [])
              ]),
              el('span', { class: 'atl-mono', style: 'font-size:12px;' }, [a.share + '%'])
            ])
          ])
        ]));
      });
    }

    // 小时分布：多天叠加会把"哪天出的事"抹掉，所以只画一天。
    // 取**轮数最多**的那天而不是列表里的第一天 —— 第一天常常是今天，
    // 而今天可能才刚开始采，一根柱子看不出任何分布。
    var day = (payload.days || []).slice().sort(function (a, b) {
      return (b.rounds || 0) - (a.rounds || 0);
    })[0];
    var chartHost = q('hour-chart');
    var dayLabel = q('hourly-day');
    if (chartHost && day) {
      if (dayLabel) dayLabel.textContent = day.day;
      var maxP50 = Math.max.apply(null,
        (day.hourly || []).map(function (h) { return h.p50 || 0; }).concat([1]));
      clear(chartHost);
      (day.hourly || []).forEach(function (h) {
        var pct = h.p50 ? Math.max(4, h.p50 / maxP50 * 100) : 0;
        chartHost.appendChild(el('div', { class: 'hour-chart__col' }, [
          el('span', {
            class: 'hour-chart__fill' + (h.rounds ? '' : ' hour-chart__fill--empty'),
            style: 'height:' + (h.rounds ? pct.toFixed(1) : 4) + '%',
            title: h.hour + ':00 · ' + (h.rounds || 0) +
                   (lang() === 'en' ? ' rounds' : ' 轮') +
                   (h.p50 ? ' · p50 ' + Math.round(h.p50) + ' ms' : '')
          }, [])
        ]));
      });
    }
  }

  function loadRange() {
    if (!pickedDays.length) { renderRange(null); return Promise.resolve(); }
    var qs = pickedDays.map(function (d) { return 'day=' + encodeURIComponent(d); }).join('&');
    return fetch('/api/day?' + qs, { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(renderRange)
      .catch(function (err) { window.console.warn('[cem] /api/day 失败', err); });
  }

  function wireHistory() {
    var grid = q('day-grid');
    if (grid) {
      grid.addEventListener('click', function (evt) {
        var node = evt.target;
        while (node && node !== grid && !node.hasAttribute('data-day')) node = node.parentNode;
        if (!node || node === grid) return;
        var day = node.getAttribute('data-day');
        var at = pickedDays.indexOf(day);
        pickedDays = at >= 0
          ? pickedDays.filter(function (d) { return d !== day; })
          : pickedDays.concat([day]).sort();
        node.classList.toggle('is-picked', at < 0);
        node.setAttribute('aria-pressed', at < 0 ? 'true' : 'false');
        updateDaysHint();
        loadRange();
      });
    }

    var all = q('days-all');
    if (all) {
      all.addEventListener('click', function () {
        pickedDays = ((lastState && lastState.history && lastState.history.days) || [])
          .map(function (d) { return d.day; });
        render(lastState);
        loadRange();
      });
    }
    var none = q('days-none');
    if (none) {
      none.addEventListener('click', function () {
        pickedDays = [];
        render(lastState);
        renderRange(null);
      });
    }
    var del = q('days-delete');
    if (del) {
      del.addEventListener('click', function () {
        if (!pickedDays.length) return;
        // 删除不可撤销，问一次。问的内容要写清删什么、删多少。
        var msg = lang() === 'en'
          ? 'Delete archived data for ' + pickedDays.length + ' day(s)?\n' +
            pickedDays.join(', ') + '\nThis cannot be undone.'
          : '删除这 ' + pickedDays.length + ' 天的归档数据？\n' +
            pickedDays.join('、') + '\n删掉之后无法恢复。';
        if (!window.confirm(msg)) return;
        post('/api/days/delete', { days: pickedDays })
          .then(function () {
            pickedDays = [];
            renderRange(null);
            return refresh();
          })
          .catch(function (err) { window.alert('删除失败：' + err.message); });
      });
    }
  }

  // ------------------------------------------------------ 遥测字段

  function renderTelemetryFields(data) {
    var host = q('telemetry-body');
    if (!host) return;
    clear(host);
    if (!data || !data.ok) {
      host.appendChild(el('p', { class: 'atl-muted', style: 'font-size:13px;' },
        [(data && data.error) || (lang() === 'en' ? 'extraction failed' : '提取失败')]));
      return;
    }

    var kv = function (k, v) {
      return el('div', { class: 'finding__grid', style: 'margin-top:0;' }, [
        el('span', { class: 'finding__key' }, [k]),
        el('span', { class: 'finding__val atl-mono', style: 'font-size:12px;' }, [v || DASH])
      ]);
    };

    host.appendChild(el('div', { class: 'atl-row', style: 'margin-bottom:var(--space-4);' }, [
      el('span', { class: 'atl-chip atl-chip--accent' }, [data.version || DASH])
    ]));
    host.appendChild(kv(lang() === 'en' ? 'intake' : '接入点', data.intake_url));
    host.appendChild(kv(lang() === 'en' ? 'token' : '凭据', data.client_token_prefix));
    host.appendChild(kv(lang() === 'en' ? 'batching' : '攒批',
      (data.flush_interval_ms ? data.flush_interval_ms + ' ms' : DASH) + ' · ' +
      (data.batch_limit ? data.batch_limit + (lang() === 'en' ? ' max' : ' 条上限') : DASH)));

    var section = function (titleZh, titleEn) {
      host.appendChild(el('h3', {
        class: 'atl-navgroup__label', style: 'margin:var(--space-5) 0 var(--space-3);'
      }, [lang() === 'en' ? titleEn : titleZh]));
    };

    if ((data.envelope || []).length) {
      section('信封字段', 'Envelope');
      var table = el('div', { class: 'exit-list' }, []);
      data.envelope.forEach(function (e) {
        table.appendChild(el('div', { class: 'exit-row' }, [
          el('span', { class: 'exit-row__ip' }, [e.key]),
          el('span', { class: 'atl-muted', style: 'font-size:12px;' }, [e.value])
        ]));
      });
      host.appendChild(table);
    }

    if ((data.payload_fields || []).length) {
      section('业务字段', 'Payload fields');
      var chips = el('div', { class: 'inv-card__tags' }, []);
      data.payload_fields.forEach(function (f) {
        chips.appendChild(el('span', { class: 'atl-chip' }, [f]));
      });
      host.appendChild(chips);
    }

    if ((data.behaviours || []).length) {
      section('代码里能读出来的行为', 'Behaviour visible in code');
      var list = el('div', { class: 'exit-list' }, []);
      data.behaviours.forEach(function (b) {
        list.appendChild(el('div', { class: 'exit-row' }, [
          el('span', { class: 'exit-row__ip' }, [b.name]),
          el('span', {}, []),
          el('span', { class: 'exit-row__meta' }, [b.meaning])
        ]));
      });
      host.appendChild(list);
    }

    if ((data.event_names || []).length) {
      section('事件名白名单（' + data.event_names.length + '）',
              'Event allowlist (' + data.event_names.length + ')');
      var ev = el('div', { class: 'inv-card__tags' }, []);
      data.event_names.slice(0, 60).forEach(function (n) {
        ev.appendChild(el('span', { class: 'atl-chip' }, [n]));
      });
      host.appendChild(ev);
      if (data.event_names.length > 60) {
        host.appendChild(el('p', { class: 'atl-muted', style: 'font-size:12px; margin-top:8px;' },
          [(lang() === 'en' ? 'and ' : '还有 ') + (data.event_names.length - 60) +
           (lang() === 'en' ? ' more — see `cem telemetry --all-events`'
                            : ' 个，跑 `cem telemetry --all-events` 全看')]));
      }
    }

    if ((data.env_vars || []).length) {
      section('相关环境变量', 'Related env vars');
      var envs = el('div', { class: 'inv-card__tags' }, []);
      data.env_vars.forEach(function (n) {
        envs.appendChild(el('span', { class: 'atl-chip atl-chip--accent' }, [n]));
      });
      host.appendChild(envs);
    }
  }

  function wireTelemetry() {
    var btn = q('telemetry-load');
    if (!btn) return;
    btn.addEventListener('click', function () {
      btn.setAttribute('disabled', 'disabled');
      var host = q('telemetry-body');
      if (host) {
        clear(host);
        host.appendChild(el('p', { class: 'atl-muted', style: 'font-size:13px;' },
          [lang() === 'en' ? 'scanning the executable…' : '正在扫描可执行文件……']));
      }
      fetch('/api/telemetry', { cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(renderTelemetryFields)
        .catch(function (err) {
          window.console.warn('[cem] /api/telemetry 失败', err);
          renderTelemetryFields(null);
        })
        .then(function () { btn.removeAttribute('disabled'); });
    });
  }

  // ------------------------------------------------------------ 渲染：状态

  function renderStatus(state) {
    var st = state.status || {};
    var sw = q('monitor-switch');
    if (sw) {
      sw.classList.toggle('is-on', !!st.running);
      sw.setAttribute('aria-checked', st.running ? 'true' : 'false');
    }

    var dot = q('status-dot');
    if (dot) dot.textContent = st.running ? '●' : '○';

    var text = q('status-text');
    if (text) {
      clear(text);
      text.appendChild(bi(
        st.running ? '监控运行中' : '监控已停止',
        st.running ? 'monitoring' : 'stopped'
      ));
    }

    var sub = q('status-sub');
    var rounds = state.rounds === undefined ? (st.samples || 0) : state.rounds;
    if (sub) {
      clear(sub);
      sub.appendChild(document.createTextNode(
        st.running
          ? (lang() === 'en' ? 'every ' : '每 ') + st.interval_s +
            (lang() === 'en' ? 's · ' : ' 秒 · ') + rounds +
            (lang() === 'en' ? ' rounds' : ' 轮')
          : (lang() === 'en' ? rounds + ' rounds in window'
                             : '窗口内 ' + rounds + ' 轮')
      ));
    }

    // 提示文字必须跟着真实间隔走。写死"每 30 秒"而实际在跑 10 秒，
    // 是界面自己在说假话。
    var hint = q('switch-hint');
    if (hint) {
      clear(hint);
      if (st.last_error) {
        hint.appendChild(el('span', { class: 'atl-muted' }, [st.last_error]));
      } else if (st.running) {
        hint.appendChild(document.createTextNode(
          lang() === 'en'
            ? 'probing every ' + st.interval_s + 's'
            : '每 ' + st.interval_s + ' 秒探测一轮'
        ));
      } else {
        hint.appendChild(bi(
          '打开后每 ' + st.interval_s + ' 秒探测一轮',
          'will probe every ' + st.interval_s + 's once on'
        ));
      }
    }

    // 用窗口里实际有多少轮，而不是采样器的自增序号：序号会算上
    // 已经被环形缓冲挤掉的轮次，界面上显示 800 轮但只画得出 720 轮的趋势。
    var kpiRounds = q('kpi-rounds');
    if (kpiRounds) kpiRounds.textContent = String(rounds);

    var seg = q('interval-seg');
    if (seg) {
      Array.prototype.forEach.call(seg.querySelectorAll('[data-interval]'),
        function (btn) {
          btn.classList.toggle(
            'is-active',
            Number(btn.getAttribute('data-interval')) === Number(st.interval_s)
          );
        });
    }
  }

  function renderKpis(state) {
    var traces = state.traces || [];
    var domains = {};
    var regions = {};
    traces.forEach(function (t) {
      domains[t.target] = 1;
      if (t.country) regions[t.country] = 1;
    });

    var dCount = Object.keys(domains).length;
    var rCount = Object.keys(regions).length;

    var kd = q('kpi-domains');
    if (kd) kd.textContent = dCount ? String(dCount) : DASH;
    var kr = q('kpi-regions');
    if (kr) kr.textContent = rCount ? String(rCount) : DASH;
    var kc = q('kpi-changes');
    if (kc) {
      var changes = (state.changes || []).filter(function (c) { return !c.first; });
      kc.textContent = (state.changes || []).length ? String(changes.length) : DASH;
    }
    var bd = q('badge-domains');
    if (bd) bd.textContent = String(dCount);

    var foot = q('foot-ts');
    if (foot) {
      foot.textContent = state.ts
        ? (lang() === 'en' ? 'last round ' : '上一轮 ') + fmtTime(state.ts)
        : DASH;
    }
  }

  // ------------------------------------------------------------ 主循环

  /** 逐个渲染器独立跑：一个面板出错不该让其他面板全空。 */
  function safely(name, fn, state) {
    try {
      fn(state);
    } catch (err) {
      // 故意打到 console.error：渲染错误必须是可见的，
      // 被静默吞掉的渲染错误看起来就只是"这块没有数据"。
      window.console.error('[cem] render ' + name + ' failed:', err);
    }
  }

  function render(state) {
    if (!state) return;
    [['status', renderStatus], ['kpis', renderKpis],
     ['surfaces', renderSurfaces], ['notes', renderNotes],
     ['telemetry', renderTelemetry], ['paths', renderPaths],
     ['changes', renderChanges], ['domains', renderDomains],
     ['connections', renderConnections], ['dns', renderDns],
     ['latency', renderLatency], ['inventory', renderInventory],
     ['findings', renderFindings], ['checks', renderChecks],
     ['stability', renderStability], ['history', renderHistory]
    ].forEach(function (pair) { safely(pair[0], pair[1], state); });
  }

  var lastState = null;

  function refresh() {
    return fetch('/api/state', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .catch(function (err) {
        // 只吞取数失败（服务端没起来时界面保持空状态）。
        window.console.warn('[cem] /api/state 取不到：', err);
        return null;
      })
      .then(function (s) {
        if (!s) return;
        lastState = s;
        render(s);           // render 内部逐个 renderer 兜异常，不再静默
      });
  }

  function connectStream() {
    if (typeof EventSource === 'undefined') {
      window.setInterval(refresh, 15000);
      return;
    }
    var es = new EventSource('/api/stream');
    es.onmessage = function (evt) {
      try {
        var msg = JSON.parse(evt.data);
        if (msg && msg.type === 'snapshot') { lastState = msg.data; render(msg.data); }
      } catch (err) { /* 单条消息坏了不该拖垮整条流 */ }
    };
    es.onerror = function () {
      es.close();
      window.setTimeout(connectStream, 4000);
    };
  }

  // ------------------------------------------------------------ 交互

  function wireSwitch() {
    var sw = q('monitor-switch');
    if (!sw) return;
    // atelier.js 已经在点击时切了 .is-on 做即时反馈。这里以服务端返回为准回写，
    // 所以请求失败时开关会自己弹回去 —— 不会出现"看着是开的其实没在跑"。
    sw.addEventListener('click', function () {
      var want = sw.classList.contains('is-on');
      var seg = q('interval-seg');
      var active = seg && seg.querySelector('.is-active[data-interval]');
      post('/api/monitor', {
        enabled: want,
        interval_s: active ? Number(active.getAttribute('data-interval')) : undefined
      }).then(function (status) {
        render(Object.assign({}, lastState || {}, { status: status }));
        return refresh();
      }).catch(function () {
        sw.classList.toggle('is-on', !want);
        sw.setAttribute('aria-checked', want ? 'false' : 'true');
      });
    });
  }

  function wireInterval() {
    var seg = q('interval-seg');
    if (!seg) return;
    Array.prototype.forEach.call(seg.querySelectorAll('[data-interval]'),
      function (btn) {
        btn.addEventListener('click', function () {
          post('/api/monitor', {
            interval_s: Number(btn.getAttribute('data-interval'))
          }).then(function (status) {
            render(Object.assign({}, lastState || {}, { status: status }));
          }).catch(function () { /* 失败时保持原值，下一次 refresh 会纠正 */ });
        });
      });
  }

  function wireSampleNow() {
    var btn = q('sample-now');
    if (!btn) return;
    btn.addEventListener('click', function () {
      btn.setAttribute('disabled', 'disabled');
      post('/api/sample', {})
        .then(refresh)
        .catch(function () { /* 忽略：状态会在下一次刷新时纠正 */ })
        .then(function () { btn.removeAttribute('disabled'); });
    });
  }

  function wireLangReflow() {
    // 语言切换后有几处文本是 JS 拼的（"经代理 x"、"每 30 秒"），重渲一遍。
    document.addEventListener('click', function (evt) {
      var t = evt.target;
      while (t && t !== document.body) {
        if (t.hasAttribute && t.hasAttribute('data-lang-toggle')) {
          window.setTimeout(function () { render(lastState); }, 0);
          return;
        }
        t = t.parentNode;
      }
    });
  }

  function boot() {
    wireSwitch();
    wireInterval();
    wireSampleNow();
    wireHistory();
    wireTelemetry();
    wireLangReflow();
    refresh().then(connectStream);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
