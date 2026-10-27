"""Prepare a reviewable patch against an existing CompleteTech control checkout.

Does not modify the supplied checkout or contact production. Run with --source.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path


def replace_once(text, needle, replacement):
    if text.count(needle) != 1:
        raise ValueError("The inspected site baseline has changed; review before patching")
    return text.replace(needle, replacement, 1)


def prepare(source, root):
    stage = root / '.work' / 'site'
    changes = {}
    path = 'theme/spintech-child/functions.php'
    old = (source / path).read_text(encoding='utf-8')
    needle = '\t$body = "Promotion: {$promo[\'id\']}\\n"'
    addition = '''\t// Canonical scope is signed and persisted before asynchronous work.
\tif ( function_exists( 'ct_scan_normalize_target' ) ) {
\t\t$target = ct_scan_normalize_target( wp_unslash( $_POST['ct_website'] ?? '' ) );
\t\tif ( is_wp_error( $target ) ) {
\t\t\twp_safe_redirect( $fail );
\t\t\texit;
\t\t}
\t\t$website = $target;
\t}

'''
    new = replace_once(old, needle, addition + needle)
    needle = "\tupdate_post_meta( $request_id, '_ct_ref', $referred_by );\n"
    addition = '''
\tif ( function_exists( 'ct_scan_on_request_ready' ) ) {
\t\t$fields = array( 'target' => $website, 'email' => $email, 'name' => $name, 'referrer' => $referred_by );
\t\t$saved = true;
\t\tforeach ( array( 'target', 'email', 'name' ) as $field ) {
\t\t\t$key = '_ct_scan_' . $field;
\t\t\tupdate_post_meta( $request_id, $key, wp_slash( $fields[ $field ] ) );
\t\t\t$saved = $saved && get_post_meta( $request_id, $key, true ) === $fields[ $field ];
\t\t}
\t\tif ( $saved && get_post_meta( $request_id, '_ct_ref', true ) === $referred_by ) {
\t\t\tdo_action( 'ct_promo_request_ready', $request_id, $fields );
\t\t} else {
\t\t\tupdate_post_meta( $request_id, '_ct_scan_enqueue_error', 'request_metadata_not_saved' );
\t\t}
\t}
'''
    new = replace_once(new, needle, needle + addition)
    changes[path] = old, new

    path = 'mu-plugins/ct-promo-terms.php'
    old = (source / path).read_text(encoding='utf-8')
    new = replace_once(old, 'Version: 1.0.0', 'Version: 1.1.0')
    new = replace_once(new, "'version' => '2026-10-21'", "'version' => '2026-10-21-r2'")
    new = replace_once(new,
        "update_post_meta( $post_id, '_ct_terms_' . $key, $acceptance[ $key ] );",
        "update_post_meta( $post_id, '_ct_terms_' . $key, wp_slash( $acceptance[ $key ] ) );")
    needle = "\tupdate_post_meta( $post_id, '_ct_terms_contract', wp_slash( $contract ) );\n"
    addition = '''\t// Queue eligibility requires a complete, durably saved acceptance record.
\t$terms_saved = get_post_meta( $post_id, '_ct_terms_contract', true ) === $contract;
\tforeach ( array( 'version', 'url', 'sha256', 'accepted_at', 'ip', 'remote_addr', 'user_agent' ) as $key ) {
\t\t$terms_saved = $terms_saved && get_post_meta( $post_id, '_ct_terms_' . $key, true ) === $acceptance[ $key ];
\t}
\tif ( $terms_saved ) {
\t\tupdate_post_meta( $post_id, '_ct_terms_saved', '1' );
\t}
'''
    new = replace_once(new, needle, needle + addition)
    changes[path] = old, new

    path = 'theme/spintech-child/templates/template-service-brief.php'
    old = (source / path).read_text(encoding='utf-8')
    new = replace_once(old,
        'Thanks &mdash; your request is in. We&rsquo;ll be in touch within one business day.',
        'Thanks &mdash; your request is saved. Watch for a separate email to confirm authorization before scanning starts. We&rsquo;ll be in touch within one business day.')
    new = replace_once(new,
        'Please fill in your name, a valid email, and your website, then try again.',
        'Please enter your name, a valid email, and your website homepage (for example, https://example.com/), then try again.')
    new = replace_once(new, 'placeholder="https://" autocomplete="url"',
        'placeholder="https://example.com/" autocomplete="url"')
    changes[path] = old, new

    path = 'content/php2shell-scan-terms.html'
    old = (source / path).read_text(encoding='utf-8')
    new = replace_once(old, 'Version 2026-10-21</strong>', 'Version 2026-10-21-r2</strong>')
    needle = '<!-- wp:heading {"level":3} -->\n<h3>2. What you authorize</h3>'
    addition = '''<!-- wp:paragraph -->
<p>Before testing starts, we send a confirmation link to the email address you entered. Open the link and press the confirmation button to confirm your authority and the website scope. Merely opening the email or link does not start a scan. Callers may send you the request link, but must not sign or confirm on your behalf. Confirmation establishes control of the email address; it does not independently prove website ownership. The signed scope is the website hostname shown on the confirmation page. Other hostnames, including a www variant, require separate authorization.</p>
<!-- /wp:paragraph -->

'''
    new = replace_once(new, needle, addition + needle)
    needle = '<!-- wp:heading {"level":3} -->\n<h3>4. What we will not do</h3>'
    addition = '''<!-- wp:paragraph -->
<p>After confirmation, the automated PHP2Shell portion checks the PHP version advertised in public response headers. A potentially affected version is not proof of exploitability, and an advertised fixed version is not proof that the website is safe. Hidden, conflicting or vendor-modified versions may be inconclusive. The other checks listed above remain part of our separate review before the full report is complete.</p>
<!-- /wp:paragraph -->

'''
    new = replace_once(new, needle, addition + needle)
    changes[path] = old, new
    patch, manifest = [], {}
    for path, (old, new) in changes.items():
        destination = stage / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(new, encoding='utf-8', newline='\n')
        patch.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                       fromfile='a/' + path, tofile='b/' + path))
        manifest[path] = {
            'before_normalized_sha256': hashlib.sha256(old.encode()).hexdigest(),
            'after_sha256': hashlib.sha256(new.encode()).hexdigest(),
        }
    (root / 'deployment' / 'complete-tech-site.patch').write_text(''.join(patch), encoding='utf-8', newline='\n')
    (root / 'deployment' / 'complete-tech-site-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('Prepared four site changes; source checkout and production unchanged.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source, Path(__file__).resolve().parents[1])
