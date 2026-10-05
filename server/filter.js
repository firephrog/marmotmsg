'use strict';
/**
 * Chat filter for a linked Discord channel. It checks what Marmot users post
 * into Discord (message text and the username shown on the webhook), because
 * that is what a Discord server opens itself to when it lets Marmot in.
 *
 * Settings, stored per link:
 *   level  'off' | 'slurs' | 'standard' | 'strict'  built-in word lists, each including the one before
 *   mode   'censor' (replace the word with *) | 'block' (refuse the message)
 *   words  extra words a moderator added; a trailing * matches any word starting with it
 *   links  true: refuse messages that contain a link
 *
 * Matching is per word, after folding case, common look-alike characters
 * (4→a, 0→o, $→s, …) and stretched letters ("fuuuck"). Entries match whole
 * words, or the start of a word when they end in *, so "class" and
 * "Scunthorpe" get through.
 */

const LEVELS = ['off', 'slurs', 'standard', 'strict'];
const MODES = ['censor', 'block'];
const MAX_WORDS = 200, MAX_WORD = 40;

const LISTS = {
  slurs: ['nigger*', 'nigga*', 'faggot*', 'fag', 'fags', 'fagg*', 'retard', 'retards', 'retarded', 'kike', 'kikes',
    'spic', 'spics', 'chink', 'chinks', 'tranny', 'trannies', 'wetback*', 'coon', 'coons', 'gook', 'gooks', 'dyke', 'dykes'],
  standard: ['fuck*', 'motherfuck*', 'fck*', 'fuk*', 'shit*', 'bullshit*', 'cunt*', 'bitch*', 'whore*', 'slut*',
    'cock', 'cocks', 'cocksuck*', 'dick', 'dicks', 'dickhead*', 'pussy', 'pussies', 'twat*', 'wank*', 'bastard*',
    'asshole*', 'arsehole*', 'jackass*', 'dumbass*', 'porn*', 'rape', 'raped', 'rapist*', 'kys'],
  strict: ['ass', 'arse', 'damn*', 'goddamn*', 'hell', 'crap*', 'piss*', 'boob*', 'tits', 'titty', 'titties', 'sex', 'sexy',
    'horny', 'nude*', 'nsfw', 'stfu', 'wtf', 'lmfao', 'idiot*', 'stupid', 'moron*']
};

const LEET = { '0': 'o', '1': 'i', '!': 'i', '3': 'e', '4': 'a', '@': 'a', '5': 's', '$': 's', '7': 't', '8': 'b', '9': 'g' };
const fold = w => w.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[0-9!@$]/g, c => LEET[c] || c);
/** An entry as a pattern where each letter may be stretched: "ass" → a+s{2,}, so "asss" is caught but "as" is not. */
const stretch = e => e.replace(/(.)\1*/g, run => run[0] + (run.length > 1 ? '{' + run.length + ',}' : '+'));

/** A word as typed: letters and digits, plus the symbols people swap in for letters ("!" only inside a word). */
const WORD = /[\p{L}\p{N}@$]+(?:!+[\p{L}\p{N}@$]+)*/gu;
const LINK = /(https?:\/\/|www\.|discord\.gg\/|\b[a-z0-9-]+\.(com|net|org|gg|io|ly|me|co|xyz|ru|tk)\b)/i;

const defaults = () => ({ level: 'off', mode: 'censor', words: [], links: false });

function normalize(f) {
  const d = defaults(); f = f || {};
  return {
    level: LEVELS.includes(f.level) ? f.level : d.level,
    mode: MODES.includes(f.mode) ? f.mode : d.mode,
    words: Array.isArray(f.words) ? f.words.filter(w => typeof w === 'string') : d.words,
    links: !!f.links
  };
}

/** True when the filter would catch something: a public channel needs this. */
const isActive = f => { f = normalize(f); return f.level !== 'off' || f.words.length > 0 || f.links; };

/** Turns a comma- or space-separated list into clean entries; bad ones are reported, not stored. */
function parseWords(s) {
  const ok = [], bad = [];
  for (const raw of String(s || '').split(/[,\s]+/)) {
    if (!raw) continue;
    const star = raw.endsWith('*'), w = fold(star ? raw.slice(0, -1) : raw).replace(/[^\p{L}\p{N}]/gu, '');
    if (!w || w.length > MAX_WORD) { bad.push(raw); continue; }
    ok.push(w + (star ? '*' : ''));
  }
  return { ok: [...new Set(ok)], bad };
}

/** One regex for one filter's settings: whole-word entries, and prefix entries that end in *. */
function compile(f) {
  f = normalize(f);
  const list = [];
  for (const lvl of LEVELS.slice(1, LEVELS.indexOf(f.level) + 1)) list.push(...LISTS[lvl]);
  list.push(...f.words);
  const exact = [], prefix = [];
  for (const e of new Set(list)) (e.endsWith('*') ? prefix : exact).push(stretch(e.replace(/\*$/, '')));
  const alts = [];
  if (exact.length) alts.push('(?:' + exact.join('|') + ')$');
  if (prefix.length) alts.push('(?:' + prefix.join('|') + ')');
  return { re: alts.length ? new RegExp('^(?:' + alts.join('|') + ')', 'u') : null, links: f.links, mode: f.mode };
}

function badWord(c, word) {
  if (!c.re) return false;
  const w = fold(word).replace(/[^\p{L}\p{N}]/gu, '');
  return !!w && c.re.test(w);
}

/**
 * Checks one piece of text. Returns {ok, text, reason}: with mode 'censor' a
 * caught word comes back starred and ok stays true; with 'block', or for a
 * link when links are refused, ok is false and reason says why.
 */
function check(f, text) {
  const c = compile(f);
  text = String(text || '');
  if (c.links && LINK.test(text)) return { ok: false, text, reason: 'links are not allowed in this channel' };
  let hit = false;
  const out = text.replace(WORD, w => { if (!badWord(c, w)) return w; hit = true; return w[0] + '*'.repeat(w.length - 1); });
  if (!hit) return { ok: true, text, hit: false };
  if (c.mode === 'block') return { ok: false, text, reason: 'this channel\'s chat filter blocked the message' };
  return { ok: true, text: out, hit: true };
}

/** True if any word of the text is on the filter (links aside): used for usernames. */
const catches = (f, text) => { const c = compile(f); return (String(text || '').match(WORD) || []).some(w => badWord(c, w)); };

function describe(f) {
  f = normalize(f);
  const words = f.words.length ? f.words.map(w => '`' + w + '`').join(', ') : 'none';
  return '**Level:** ' + f.level + (f.level === 'off' ? '' : ' (' + { slurs: 'slurs only', standard: 'slurs and swearing', strict: 'slurs, swearing and mild language' }[f.level] + ')') + '\n' +
    '**Mode:** ' + (f.mode === 'block' ? 'block the message' : 'censor the word') + '\n' +
    '**Links:** ' + (f.links ? 'blocked' : 'allowed') + '\n' +
    '**Extra words (' + f.words.length + '):** ' + words;
}

module.exports = { LEVELS, MODES, MAX_WORDS, defaults, normalize, isActive, parseWords, check, catches, describe };
