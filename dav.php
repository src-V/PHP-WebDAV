<?php
/*
  PHP-WebDAV
  AGPL-3.0-or-later

  blabla
  short config/autoupdate explain
  blabla

  For more information, see below the licence notice.
*/

$_CONFIG = [
  'admin_password'  => 'CHANGEME',
  'users'           => ['user' => 'CHANGEME'],
  'root'            => dirname(__FILE__),
  'session_timeout' => 900
];

/*
  Copyright V.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
  README.md

  blabla
  blabla
*/

/******************************************************************************/
/******************************************************************************/

main();

function main() {
  date_default_timezone_set('UTC');

  check_web_interface();

  authenticate_or_exit();

  setup_xattr();

  call_if_exists('method_'.strtolower($_SERVER['REQUEST_METHOD']));

  exit_with_response_code(501);
}

function davlog($text) {
  @file_put_contents('dav.log', $text, FILE_APPEND);
}

function check_web_interface() {
  global $_CONFIG;

  if (array_search($_SERVER['REQUEST_METHOD'], ['GET', 'POST']) === false)
    return;

  // Don't function_exists(). Not authenticated yet.
  if (array_search($_SERVER['QUERY_STRING'], ['css', 'js', 'user', 'admin', 'diff']) !== false) {
    call_user_func('page_'.$_SERVER['QUERY_STRING']);
    exit;
  }

  if (!isset($_CONFIG['users']) || count($_CONFIG['users']) == 0) {
    page_index();
    exit;
  }
}

function auth_digest() {
  global $_CONFIG;
  
  $realm = 'PHP-WebDAV';

  if (empty($_SERVER['PHP_AUTH_DIGEST'])) {
      header('HTTP/1.1 401 Unauthorized');
      header('WWW-Authenticate: Digest realm="'.$realm.
             '",qop="auth",nonce="'.uniqid().'",opaque="'.md5($realm).'"');

      die('Text to send if user hits Cancel button');
  }


  // analyze the PHP_AUTH_DIGEST variable
  if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST'])) ||
      !isset($_CONFIG['users'][$data['username']]))
      die('Wrong Credentials!');


  // generate the valid response
  $A1 = md5($data['username'] . ':' . $realm . ':' . $_CONFIG['users'][$data['username']]);
  $A2 = md5($_SERVER['REQUEST_METHOD'].':'.$data['uri']);
  $valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

  if ($data['response'] != $valid_response)
      die('Wrong Credentials!');

  // ok, valid username & password
  $_SERVER['PHP_AUTH_USER'] = $data['username'];
}

// function to parse the http auth header
function http_digest_parse($txt)
{
    // protect against missing data
    $needed_parts = ['nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1];
    $data = [];
    $keys = implode('|', array_keys($needed_parts));

    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

    foreach ($matches as $m) {
        $data[$m[1]] = $m[3] ? $m[3] : $m[4];
        unset($needed_parts[$m[1]]);
    }

    return $needed_parts ? false : $data;
}


function authenticate_or_exit() {
  davlog(date('j M H:i:s').' ');

  if (!authenticated()) {
    if (isset($_SERVER['PHP_AUTH_USER']))
      davlog('Failed login (user: '.$_SERVER['PHP_AUTH_USER'].' password: '.$_SERVER['PHP_AUTH_PW'].' ');
    else
      davlog('Not authenticated (');
    
    davlog('method: '.$_SERVER['REQUEST_METHOD'].' request: '.$_SERVER['REQUEST_URI'].")\n");

    // FIXME: digest?
    header('WWW-Authenticate: Basic realm="DAV"');
    exit_with_response_code(401);
  }

  davlog('('.$_SERVER['PHP_AUTH_USER'].') ');
}

function authenticated() {
  global $_CONFIG;

  auth_digest();
  return true;

  if (!isset($_SERVER['PHP_AUTH_USER']))
    return false;

  if ($_SERVER['PHP_AUTH_USER'] != $_CONFIG['user'] || $_SERVER['PHP_AUTH_PW'] != $_CONFIG['password'])
    return false;

  return true;
}

function call_if_exists($function) {
  global $_CONFIG;

  davlog($_SERVER['REQUEST_METHOD'].' ');

  if (($target = preg_replace('!^'.$_SERVER['SCRIPT_NAME'].'!', '', $_SERVER['REQUEST_URI'])) == '')
    $target = '/';

  // FIXME: hack.
  if ($function == 'method_put')
    $content = '';
  else
    $content = file_get_contents('php://input');

  if (function_exists($function)) {
// FIXME
if (isset($_SERVER['HTTP_X_LITMUS']))
  davlog($_SERVER['HTTP_X_LITMUS'].' ');
    davlog(quoted_printable_encode($target)."\n");
    $function($_CONFIG['root'], $target, $content);
    exit;
  }

  davlog('ERROR: Not Implemented ('.quoted_printable_encode($target).")\n");
  davlog('$content = '.var_export($content, true)."\n");
  davlog('$_SERVER = '.var_export($_SERVER, true)."\n");
}

/******************************************************************************/
/******************************************************************************/

// FIXME: implement head, post, trace, lock, unlock & orderpatch.
function method_options($root, $target, $content) {
  header('Allow: OPTIONS, MKCOL, GET, PUT, DELETE, COPY, MOVE, PROPFIND, PROPPATCH');
  header('Allow: HEAD, POST, TRACE, PROPPATCH, LOCK, UNLOCK, ORDERPATCH', false);
  header('DAV: 1, 2');
}

function method_mkcol($root, $target, $content) {
  if ($content != '')
    exit_with_response_code(415);

  if (file_exists($root.$target))
    exit_with_response_code(405);

  if (!@mkdir($root.$target, 0777, false))
    exit_with_response_code(409);
}

function method_head($root, $target, $content) {
  head_get(false, $root, $target, $content);
}

function method_get($root, $target, $content) {
  head_get(true, $root, $target, $content);
}

function head_get($get, $root, $target, $content) {
/*
  // no litmus test.
  if ($content != '')
    exit_with_response_code(415);
*/

  // FIXME should be 404. no litmus test.
  if (!file_exists($root.$target))
    exit_with_response_code(400);

  // FIXME does rfc require this?
  header('Content-Length: '.filesize($root.$target));

  if ($get) {
    while (ob_get_level()) ob_end_clean();
    readfile($root.$target);
  }
}

function method_put($root, $target, $content) {
  if (!file_exists($root.$target))
    http_response_code(201);

  // FIXME no litmus test for fails.
  $input = fopen('php://input', 'r');
  $file = fopen($root.$target, 'w');
  while ($data = fread($input, 4096))
    fwrite($file, $data);
  fclose($file);
  fclose($input);
}

function method_delete($root, $target, $content) {
/*
  // no litmus test.
  if ($content != '')
    exit_with_response_code(415);
*/

  if (!file_exists($root.$target))
    exit_with_response_code(404);

  // FIXME no litmus test for fails.
  rm($root.$target);
}

function method_copy($root, $target, $content) {
  copy_move('cp', $root, $target, $content);
}

function method_move($root, $target, $content) {
  copy_move('rename', $root, $target, $content);
}

// FIXME: support depth 0 as per RFC?
function copy_move($function, $root, $source, $content) {
  $destination = destination();

  if (!file_exists($root.$destination))
    http_response_code(201);

  if (file_exists($root.$destination) && $_SERVER['HTTP_OVERWRITE'] != 'T')
    exit_with_response_code(412);

  if (file_exists($root.$destination)) {
    http_response_code(204);
    rm($root.$destination);
    $destination = preg_replace('!/$!', '', $destination);
  }

  if (!$function($root.$source, $root.$destination))
    exit_with_response_code(409);
}

function method_propfind($root, $target, $content) {
  // FIXME: no litmus test.
  if (!file_exists($root.$target))
    exit_with_response_code(404);

  if ($content == '')
    $content = '<?xml version="1.0" encoding="utf-8" ?><propfind xmlns="DAV:"><allprop/></propfind>';

  if (($content = simplexml_load_string($content, 'SimpleXMLElement', LIBXML_NOCDATA)) === false)
    exit_with_response_code(400);

  if ($content->getNamespaces(true)[''] != 'DAV:')
    exit_with_response_code(400);

  // FIXME
  if (isset($content->allprop)) {
    if (!isset($content->prop))
      $content->addChild('prop');
//    foreach (preg_filter('/^prop_(.*)/', '$1', get_defined_functions()['user']) as $prop)
    foreach (['creationdate', 'displayname', 'getcontentlanguage', 'getcontentlength',
              'getcontenttype', 'getetag', 'getlastmodified', 'lockdiscovery', 'resourcetype',
              'source', 'supportedlock'] as $prop)
      $content->prop->addChild($prop);
  }

  $xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8" ?><multistatus xmlns="DAV:"></multistatus>');
  propfind_response($root, $target, $content, $xml);

  if ($_SERVER['HTTP_DEPTH'] === '1')
    foreach (scandir($root.'/'.$target) as $file) {
      if ($file == '.' || $file == '..')
        continue;

      propfind_response($root, $target.'/'.$file, $content, $xml);
    }

  $dom = new DOMDocument;
  $dom->preserveWhiteSpace = false;
  $dom->loadXML($xml->saveXML());
  $dom->formatOutput = true;
  $xml = $dom->saveXML();

  http_response_code(207);
  echo $xml;
}

function propfind_response($root, $file, $content, &$xml) {
  if ($file == '')
    $file = '/';
 
  // FIXME: HTTP/1.1 should not be hardcoded, neither should the status text (localization).
  $response = $xml->addChild('response');
  $response->addChild('href', $_SERVER['SCRIPT_NAME'].$file);
  $propstat_valid = $response->addChild('propstat');
  $propstat_valid->addChild('prop');
  $propstat_valid->addChild('status', 'HTTP/1.1 200 OK');
  $propstat_invalid = $response->addChild('propstat');
  $propstat_invalid->addChild('prop');
  $propstat_invalid->addChild('status', 'HTTP/1.1 404 Not Found');

  if (is_dir($root.$file) && substr($root.$file, -1) != '/')
    $response->href .= '/';

  $stats = stat($root.'/'.$file);

  foreach ($content->prop->children() as $prop) {
    if (($namespace = array_values($prop->getNamespaces(true))[0]) == null)
      $namespace = '';
    $name = $prop->getName();

    if ($namespace == 'DAV:') {
      switch (strtolower($name)) {
        case 'creationdate':
          if (!is_dir($root.'/'.$file))
            $propstat_valid->prop->addChild($name, date('Y-m-d\TH:i:s\Z', $stats['ctime']), $namespace);
          else
            $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'displayname':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'getcontentlanguage':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'getcontentlength':
          if (!is_dir($root.'/'.$file))
            $propstat_valid->prop->addChild($name, $stats['size'], $namespace);
          else
            $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'getcontenttype':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'getetag':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'getlastmodified':
          $propstat_valid->prop->addChild($name, date('D, j M Y H:i:s \G\M\T', $stats['mtime']), $namespace);
          break;
        case 'lockdiscovery':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'resourcetype':
          if (is_dir($root.'/'.$file))
            $propstat_valid->prop->addChild($name, null, $namespace)->addChild('collection');
          else
            $propstat_valid->prop->addChild($name, null, $namespace)->addChild('file');
          break;
        case 'source':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        case 'supportedlock':
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
        default:
          $propstat_invalid->prop->addChild($name, null, $namespace);
          break;
      }
    } else {
      $value = xattr_get($root.'/'.$file, "PHP-WebDAV['".$namespace."']['".$name."']");
      if ($value != '')
        $propstat_valid->prop->addChild($name, $value, $namespace);
      else
        $propstat_invalid->prop->addChild($name, null, $namespace);
    }
  }

  if (isset($content['allprop']))
    unset($propstat_invalid[0]);
}

function method_proppatch($root, $target, $content) {
  // FIXME: no litmus test.
  if (!file_exists($root.$target))
    http_response_code(404);

  // FIXME: no litmus tests?
  if ($content != "") {
    //if (($content = simplexml_load_string($content, 'SimpleXMLElement', LIBXML_NOCDATA, 'DAV:')) === false)
    if (($content = simplexml_load_string($content)) === false)
      exit_with_response_code(400);

    // FIXME: ??? why not here?
    //if ($content->getNamespaces(true)[''] != 'DAV:')
    //  exit_with_response_code(400);

    $props = [];  
    foreach ($content->xpath("//*[local-name()='prop']") as $prop) {
      $mode = $prop->xpath("..")[0]->getName();
      $namespace = $prop->children()->getNamespaces(true);
      if (count($namespace))
        $namespace = $namespace[0];
      else
        $namespace = 'DAV:';
      $name = $prop->children($namespace)->getName();
      $value = (string)$prop->children($namespace)->$name;

      switch ($mode) {
        case 'set':
          xattr_set($root.$target, "PHP-WebDAV['".$namespace."']['".$name."']", $value);
          break;
        case 'remove':
          xattr_remove($root.$target, "PHP-WebDAV['".$namespace."']['".$name."']");
          break;
        default:
          davlog('Unknown mode: '.$mode."\n");
          break;
      }
      array_push($props, ['mode' => $mode, 'namespace' => $namespace, 'name' => $name, 'value' => $value]);
    }

    $content = $props;
  } else {
    $content = [];
  }
}

function method_lock($root, $target, $content) {
  davlog('$_SERVER = '.var_export($_SERVER, true)."\n");
  davlog('$content = '.var_export($content, true)."\n");
}

function method_unlock($root, $target, $content) {
  davlog('$_SERVER = '.var_export($_SERVER, true)."\n");
  davlog('$content = '.var_export($content, true)."\n");
}

/******************************************************************************/
/******************************************************************************/

function exit_with_response_code($code) {
  http_response_code($code);
  exit;
}

function rm($target) {
  if (is_link($target) || !is_dir($target))
    return unlink($target);

  chmod($target, 0777);

  foreach (scandir($target) as $file) {
    if ($file == '.' || $file == '..')
      continue;
    if (!rm($target.DIRECTORY_SEPARATOR.$file))
      return false;
  }

  return rmdir($target);
}

// FIXME: make it do exactly what cp -ap does. does not do that atm. also, depth.
function cp($source, $destination) {
  if ($_SERVER['HTTP_DEPTH'] === '0' && is_dir($source)) {
    if (file_exists($destination)) {
      $result_code = !mkdir($destination.'/'.$source);
    } else {
      $result_code = !mkdir($destination);
    }
  } else {
    exec('cp -ap "'.$source.'" "'.$destination.'" 2>&1', $output, $result_code); 
  }

  return !$result_code;

  if (!is_dir($source)) {
    if (is_dir($destination))
      $destination .= DIRECTORY_SEPARATOR.filename($source);

    $destination = preg_replace('!/$!', '', $destination);
    return copy($source, $destination);
  }

  if (is_dir($destination)) {
    if (!mkdir($destination.DIRECTORY_SEPARATOR.filename($source)))
      return false;
    $destination = $destination.DIRECTORY_SEPARATOR.filename($source);
  }

  foreach (scandir($source) as $file) {
    if ($file == '.' || $file == '..')
      continue;
    if (!cp($source.DIRECTORY_SEPARATOR.$file, $destination))
      return false;
  }

  return true;
}

function setup_xattr() {
  if (!function_exists('xattr_list')) {
    function xattr_list($filename, $flags = 0) {
      exec('attr -ql '.escapeshellarg($filename), $output);
      return $output;
    }

    function xattr_set($filename, $name, $value, $flags = 0) {
      exec('attr -qs '.escapeshellarg($name).' -V '.escapeshellarg($value).' '.escapeshellarg($filename));
      return true;
    }

    function xattr_get($filename, $name, $flags = 0) {
      return exec('attr -qg '.escapeshellarg($name).' '.escapeshellarg($filename));
    }

    function xattr_remove($filename, $name, $flags = 0) {
      exec('attr -qr '.escapeshellarg($name).' '.escapeshellarg($filename));
      return true;
    }
  }
}

function destination() {
  $scheme = ((!empty($_SERVER['HTTPS'] && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) ? 'https://' : 'http://');
  $destination = preg_replace('!'.$scheme.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME'].'!', '', $_SERVER['HTTP_DESTINATION']);

  // FIXME: check if destination is a remote host? does webdav support that? It does... Do we?
  return $destination;
}

function array_to_xml($array, $root) {
  $xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8" ?><'.$root.' xmlns="DAV:"></'.$root.'>');
  _array_to_xml($array, $xml);

  $dom = new DOMDocument;
  $dom->preserveWhiteSpace = false;
  $dom->loadXML($xml->saveXML());
  $dom->formatOutput = true;

  return $dom->saveXML();
}

function _array_to_xml($array, $xml) {
  if (is_array($array)) {
    foreach($array as $key => $value) {
      if (is_numeric($key)) {
        if ($key == 0) {
          $node = $xml;
        } else {
          $parent = $xml->xpath('..')[0];
          $node = $parent->addChild($xml->getName());
        }
      } else {
        $node = $xml->addChild($key);
      }
      _array_to_xml($value, $node);
    }
  } else {
    $xml[0] = $array;
  }
}

/*
function script_url() {
  // FIXME: do we need to add portnumbers? likely?
  return ((!empty($_SERVER['HTTPS'] && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) ? 'https://' : 'http://').
         $_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME'];
}
*/

/******************************************************************************/
/******************************************************************************/

function update() {
  // download if newer to dav.new.php
  // run new dav (in namespace?) which will do the upgrading, 
  // importing config & replacing dav.php
  // check signatures before run and as checksum after config import
}

/******************************************************************************/
/******************************************************************************/

function session() {
  session_name('PHP-WebDAV');
  session_start();
}

function array_validate(&$array, $defaults) {
  foreach ($defaults as $key => $value)
    if (!isset($array[$key]))
      $array[$key] = $value;
}

function array_unset(&$array, $keys) {
  foreach ($keys as $key)
    unset($array[$key]);
}

function page_css() {
  header('Content-Type: text/css');
?>
  #content {
    position: absolute;
    top: 25px;
    left: 50%;
    transform: translate(-50%, 0);
  }

  #title {
    width: 280px;
    text-align: center;
  }

  .right {
    width: 280px;
    text-align: right;
  }
<?php
}

function page_js() {
?>
  // JS
<?php
}

function page_index() {
  // FIXME: admin change pass timeout based on file modify/create time.

  $dom = base_page('PHP-WebDAV');
  $content = (new Element($dom->getElementById('content')));
  $content->add('p')->append('blabla<br/>blabla');
  $content->add('p')->append('click: ')->add('a', ['href' => $_SERVER['SCRIPT_NAME'].'?admin'], 'Admin')->parent()->append('.<br/>');
  $content->add('p')->append('click: ')->add('a', ['href' => $_SERVER['SCRIPT_NAME'].'?user'], 'User')->parent()->append('.');

  echo $dom->saveHTML();
}

// FIXME: check timeout in post too
function page_user() {
  global $_CONFIG;

  session();
  array_validate($_SESSION, ['user' => '', 'user_remote_addr' => '', 'user_login_error' => false,
                             'user_validated' => false, 'user_last_seen' => 0]);

  if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!$_SESSION['user_validated']) {
      array_validate($_POST, ['user' => '', 'password' => '']);

      // FIXME: force user/password to be non-empty
      if (!array_key_exists($_POST['user'], $_CONFIG['users']) || $_CONFIG['users'][$_POST['user']] != $_POST['password']) {
        if ($_POST['user'] != '' || $_POST['password'] != '')
          $_SESSION['user_login_error'] = true;          
      } else {
        session_regenerate_id(true);

        $_SESSION['user'] = $_POST['user'];
        $_SESSION['user_remote_addr'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_last_seen'] = time();
        $_SESSION['user_validated'] = true;
      }
    } elseif (isset($_POST['logout']) && $_POST['logout'] == 'Logout') {
      array_unset($_SESSION, ['user', 'user_remote_addr', 'user_validated', 'user_last_seen', 'user_login_error', 'user_change_result']);
    } else {
      user_post($_SESSION['user']);
    }

    redirect($_SERVER['REQUEST_URI']);
  }

  if (!$_SESSION['user_validated'] || $_SESSION['user_remote_addr'] != $_SERVER['REMOTE_ADDR'] ||    
      $_SESSION['user_last_seen'] < (time() - $_CONFIG['session_timeout'])) {
    array_unset($_SESSION, ['user', 'user_remote_addr', 'user_last_seen']);
    $_SESSION['user_validated'] = false;
  } else {
    $_SESSION['user_last_seen'] = time(); 
  }

  $dom = base_page('PHP-WebDAV');
  $form = (new Element($dom->getElementById('content')))->add('form', ['method' => 'post']);
  
  if (!$_SESSION['user_validated']) {
    $div = $form->add('p')->add('div', ['class' => 'right'])->append('Username:&#160;');
    $div->add('input', ['type' => 'text', 'name' => 'user', 'size' => '28']);
    $div = $form->add('p')->add('div', ['class' => 'right'])->append('Password:&#160;');
    $div->add('input', ['type' => 'password', 'name' => 'password', 'placeholder' => '********', 'size' => '28']);
    $form->add('p')->add('div', ['class' => 'right'])->add('input', ['type' => 'submit', 'value' => 'Login']);
    if ($_SESSION['user_login_error']) {
      $form->add('p')->add('div', ['class' => 'right'])->append('Username and/or password invalid.');
      $_SESSION['user_login_error'] = false;
    }
  } else {
    user($dom, $form, $_SESSION['user']);
  }

  echo $dom->saveHTML();
}

function user(&$dom, &$form, $user) {
  $form->append('Hi '.$user.'!');
  $form->append('<br/>Old password:&#160;')->add('input', ['type' => 'password', 'name' => 'oldpassword', 'placeholder' => '********', 'size' => '28']);
  $form->append('<br/>New password:&#160;')->add('input', ['type' => 'password', 'name' => 'newpassword', 'placeholder' => '********', 'size' => '28']);
  $form->append('<br/>Repeat new password:&#160;')->add('input', ['type' => 'password', 'name' => 'repeatpassword', 'placeholder' => '********', 'size' => '28']);
  $form->append('<br/>')->add('input', ['type' => 'submit', 'name' => 'change', 'value' => 'Change Password']);
  $form->add('input', ['type' => 'submit', 'name' => 'logout', 'value' => 'Logout']);
  if (isset($_SESSION['user_change_result'])) {
    $form->add('p')->append($_SESSION['user_change_result']);
    unset($_SESSION['user_change_result']);
  }
}

function user_post($user) {
  global $_CONFIG;

  if ($_POST['oldpassword'] == '')
    return;

  if ($_POST['oldpassword'] != $_CONFIG['users'][$user]) {
    $_SESSION['user_change_result'] = 'Old password invalid.';
    return;
  }
  
  if ($_POST['newpassword'] == '') {
    $_SESSION['user_change_result'] = 'New password can not be empty.';
    return;
  }
  
  if ($_POST['newpassword'] != $_POST['repeatpassword']) {
    $_SESSION['user_change_result'] = 'New passwords not the same.';
    return;
  }

  change_user_password($user, $_POST['newpassword']);

  $_SESSION['user_change_result'] = 'Password changed.';
}

// FIXME: check timeout in post too
function page_admin() {
  global $_CONFIG;

  session();
  array_validate($_SESSION, ['admin_remote_addr' => '', 'admin_login_error' => false,
                             'admin_validated' => false, 'admin_last_seen' => 0]);

  if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!$_SESSION['admin_validated']) {
      array_validate($_POST, ['password' => '']);

      // FIXME: force passwords to be non-empty
      if ($_POST['password'] != $_CONFIG['admin_password']) {
        if ($_POST['password'] != '')
          $_SESSION['admin_login_error'] = true;          
      } else {
        session_regenerate_id(true);

        $_SESSION['admin_remote_addr'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['admin_last_seen'] = time();
        $_SESSION['admin_validated'] = true;
      }
    } elseif (isset($_POST['logout']) && $_POST['logout'] == 'Logout') {
      array_unset($_SESSION, ['admin_remote_addr', 'admin_validated', 'admin_last_seen', 'admin_login_error']);
    } else {
      admin_post();
    }

    redirect($_SERVER['REQUEST_URI']);
  }

  if (!$_SESSION['admin_validated'] || $_SESSION['admin_remote_addr'] != $_SERVER['REMOTE_ADDR'] ||    
      $_SESSION['admin_last_seen'] < (time() - $_CONFIG['session_timeout'])) {
    array_unset($_SESSION, ['admin_remote_addr', 'admin_last_seen']);
    $_SESSION['admin_validated'] = false;
  } else {
    $_SESSION['admin_last_seen'] = time(); 
  }

  $dom = base_page('PHP-WebDAV Admin');
  $form = (new Element($dom->getElementById('content')))->add('form', ['method' => 'post']);

  if (!$_SESSION['admin_validated']) {
    $form->append('Password:&#160;');
    $form->add('input', ['type' => 'password', 'name' => 'password', 'placeholder' => '********', 'size' => '22']);
    $form->append('&#160;');
    $form->add('input', ['type' => 'submit', 'value' => 'Login']);
    if ($_SESSION['admin_login_error']) {
      $form->add('p')->append('Password invalid.');
      $_SESSION['admin_login_error'] = false;
    }
  } else {
    admin($dom, $form);
  }

  echo $dom->saveHTML();
}

function admin(&$dom, &$form) {
  global $_CONFIG;
  
  if (count($_CONFIG['users']) > 0) {
    $table = $form->add('table');
    $row = $table->add('tr');
    $row->add('td')->append('User');
    $row->add('td')->append('Password');
    $row->add('td', ['colspan' => '2']);
    foreach ($_CONFIG['users'] as $user => $password) {
      $row = $table->add('tr');
      $row->add('td')->append($user);
      $row->add('td')->add('input', ['type' => 'text', 'name' => 'password['.$user.']', 'value' => $password, 'size' => '28']);;
      $row->add('td')->add('input', ['type' => 'submit', 'name' => 'change['.$user.']', 'value' => 'Change Password']);
      $row->add('td')->add('input', ['type' => 'submit', 'name' => 'delete['.$user.']', 'value' => 'Delete']);
    }
  }

  $form->add('p')->append('Username:&#160;')->add('input', ['type' => 'text', 'name' => 'new_user', 'size' => '28']);
  $p = $form->add('p')->append('Password:&#160;');
  $p->add('input', ['type' => 'text', 'name' => 'new_password', 'placeholder' => '********', 'size' => '28']);
  $p->append('&#160;')->add('input', ['type' => 'submit', 'name' => 'add', 'value' => 'Add User']);
  $p = $form->add('p')->add('input', ['type' => 'submit', 'name' => 'diff', 'value' => 'Show diff'])->parent();
  $p->append('&#160;')->add('input', ['type' => 'submit', 'name' => 'logout', 'value' => 'Logout']);
}

function admin_post() {
  if (isset($_POST['change']))
    change_user_password(key($_POST['change']), $_POST['password'][key($_POST['change'])]);
  elseif (isset($_POST['add']))
    add_user($_POST['new_user'], $_POST['new_password']);
  elseif (isset($_POST['delete']))
    delete_user(key($_POST['delete']));
  elseif (isset($_POST['diff']))
    redirect($_SERVER['SCRIPT_NAME'].'?diff');
}

function page_diff() {
  session();
  array_validate($_SESSION, ['admin_validated' => false]);

  // FIXME: session validation & timeout
  if (!$_SESSION['admin_validated'] || ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['back'])))
    redirect($_SERVER['SCRIPT_NAME'].'?admin');

  if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['dist'])) {
    make_dist();
    redirect($_SERVER['REQUEST_URI']);
  }

  $dom = base_page('PHP-WebDAV Diff');
  $content = (new Element($dom->getElementsByTagName('body')[0]));
  $content->element->removeChild($content->element->firstChild);
  $form = $content->add('form', ['method' => 'post'])->add('p');
  $form->add('input', ['type' => 'submit', 'name' => 'back', 'value' => 'Back']);
  $form->append('&#160;')->add('input', ['type' => 'submit', 'name' => 'dist', 'value' => 'Make Dist']);
  if (isset($_SESSION['dist_result'])) {
    $form->append('&#160;&#160;'.$_SESSION['dist_result']);
    unset($_SESSION['dist_result']);
  }
  $table = $content->add('table', ['cellspacing' => '0']);

  // FIXME: preferably do the diff in php
  // FIXME: don't hardcode paths
  exec('diff --strip-trailing-cr -u dist/dav.php dav.php | awk \'FNR < 3 {next} /^@/ {match($2, /.([^,]+)/, a); l = a[1]; match($3, /.([^,]+)/, a); r = a[1]; print "@:::" $0} /^\-/ {print "-:" l++ "::" $0} /^\+/ {print "+::" r++ ":" $0} /^ / {print "=:" l++ ":" r++ ":" $0}\'', $diff);

  $colors = ['@' => ['#badfff', '#ddf4ff'], '=' => ['#ffffff', '#ffffff'],
             '-' => ['#ffd7d5', '#ffebe9'], '+' => ['#ccffd8', '#e6ffec']];

  foreach ($diff as $line) {
    $row = $table->add('tr');
    preg_match('/^(.):([0-9]*):([0-9]*):(.*)$/', $line, $matches);
    list(, $color, $old_line_number, $new_line_number, $line) = $matches;
    $line = '<code>'.str_replace(' ', '&#160;', htmlspecialchars($line, ENT_XML1, 'UTF-8')).'</code>';

    if ($color == '@') {
      $row->add('td', ['colspan' => '2', 'style' => 'background: '.$colors[$color][0].';']);
    } else {
      $row->add('td', ['style' => 'background: '.$colors[$color][0].';'])->append('&#160;&#160;'.$old_line_number.'&#160;&#160;');
      $row->add('td', ['style' => 'background: '.$colors[$color][0].';'])->append('&#160;&#160;'.$new_line_number.'&#160;&#160;');
    }

    $row->add('td', ['style' => 'background: '.$colors[$color][1].';'])->append($line);
  }

  echo $dom->saveHTML();
  exit;
}

function make_dist() {
  // FIXME: do it in php. no fixed filenames. error checking (mkdir). Do check local TZ for rename.
  mkdir('dist');
  exec("sed -r \"s/( *'admin_password' *=> ').*(',?)/\\1CHANGEME\\2/;s/( *'users' *=> \\[').*(' => ').*('\\],?)/\\1user\\2CHANGEME\\3/\" dav.php > dist/dav.php");
  // FIXME: timezone hack
  //$dated_file = 'dav.'.date('YMD-His', stat('dist/dav.php')['mtime']).'.php';
  $dated_file = 'dav.'.exec('date -d @$(stat -c %Y dist/dav.php) +%Y%m%d-%H%M%S').'.php';
  exec('cp -ap dist/dav.php dist/'.$dated_file);

  $_SESSION['dist_result'] = 'File dist/'.$dated_file.' created.';
}

function change_user_password($user, $password) {
  global $_CONFIG;

  echo 'change: '.$user.' '.$password;
  exit;
}

function add_user($user, $password) {
  global $_CONFIG;

  echo 'add: '.$user.' '.$password;
  exit;
}

function delete_user($user) {
  global $_CONFIG;

  echo 'delete: '.$user;
  exit;
}

function redirect($to) {
  header('Location: '.$to);
  exit;
}

function base_page($title) {
  $dom = DOMImplementation::createDocument(null, 'html', DOMImplementation::createDocumentType('html'));
  $dom->formatOutput = true;

  $html = new Element($dom->documentElement);
  $head = $html->add('head');
  $head->add('title', null, $title);
  $head->add('link', ['rel' => 'stylesheet', 'href' => $_SERVER['SCRIPT_NAME'].'?css']);
  $head->add('script', ['src' => $_SERVER['SCRIPT_NAME'].'?js']);
  $html->add('body')->add('div', ['id' => 'content'])->add('div', ['id' => 'title'])->add('h4', null, $title);

  return $dom;
}

class Element {
  public $element;
  public $dom;

  function __construct($element) {
    $this->element = $element;
    $this->dom = $element->ownerDocument;
  }

  public function add($name, $attributes = null, $value = null) {
    $this->element->appendChild($node = $this->dom->createElement($name));

    // FIXME: set '' as id namespace instead of xml:
    if ($attributes !== null)
      foreach ($attributes as $attribute_name => $attribute_value) {
        $node->setAttribute($attribute_name, $attribute_value);
        if ($attribute_name == 'id')
          $node->setIdAttribute('id', true);
      }

    if ($value !== null)
      $node->appendChild($this->dom->createTextNode($value));

    return new Element($node);
  }

  public function append($xml) {
    if (trim($xml) != '') {
      $fragment = $this->dom->createDocumentFragment();
      $fragment->appendXML($xml);
      $this->element->appendChild($fragment);
    }
    
    return $this;
  }
  
  public function parent() {
    return new Element($this->element->parentNode);
  }
}
