<?php

/**
 * mdt is Magento Developer Tool
 * @author <a.yahnenko@gmail.com>
 *
 * @todo
 * secure page with password
 * modules rewrites count and files list
 * fix crash on cache table not found (magento 1.3)
 *
 * me not perfekt! see bug - kontakt developr!
 */

require_once('auth_ip_check.php');
require_once('auth.php');
error_reporting(-1);
ini_set('display_errors', 1);
define ('MAGENTO_BASE_PATH', dirname(dirname(__FILE__)).'/');

class MdtApp
{
    private static $config = array(
        'username' => 'admin',
        'password' => 'admin',
        'modules' => array(
            'dashboard',
            'logs',
            'reports',
        ),
        'default_module' => 'dashboard'
    );

    private static $request = null;

    private static $modules = null;
    private static $messages = array();
    private static $contentHtml = null;

    public static function getVersion()
    {
        return '076';
    }

    // processing

    public static function process()
    {
        $moduleClassName = self::getModuleClassName(self::getModuleName());

        if (!class_exists($moduleClassName))
        {
            self::error('module class not found: ' . $moduleClassName);
        }

        $module = new $moduleClassName();

        self::$contentHtml = $module->process();
    }

    public static function getModules()
    {
        foreach (self::getConfig('modules') as $moduleName)
        {
            $moduleClassName = MdtApp::getModuleClassName($moduleName);
            $module = new $moduleClassName();

            self::$modules[] = array(
                'name' => $moduleName,
                'selected' => $moduleName == self::getModuleName(),
                'url' => self::getUrl($moduleName),
                'counter' => $module->getCounter()
            );
        }
        return self::$modules;
    }

    public static function getMessages()
    {
        return self::$messages;
    }

    public static function getContentHtml()
    {
        return self::$contentHtml;
    }

    public static function getModuleName()
    {
        $request = self::getRequest();
        return isset($request[0]) ? $request[0] : self::getConfig('default_module');
    }

    public static function getRequest($position = null)
    {
        if (null == self::$request)
        {
            $request = str_replace($_SERVER['SCRIPT_NAME'], '', $_SERVER['REQUEST_URI']);
            $request = explode('/', $request);

            foreach ($request as $key => $parameter)
            {
                if (empty($parameter))
                {
                    unset($request[$key]);
                }
            }

            self::$request = array_values($request);
        }

        if (null === $position)
        {
            return self::$request;
        }

        return isset(self::$request[$position]) ? self::$request[$position] : null;
    }

    public static function resetRequest()
    {
        self::$request = array();
    }

    public static function getModuleClassName($moduleName)
    {
        return 'Mdt' . ucfirst(strtolower($moduleName)) . 'Module';
    }

    public static function getConfig($variable)
    {
        return self::$config[$variable];
    }

    // messages

    public static function error($text, $die = true)
    {
        if ($die)
        {
            die ('<div class="message error">' . $text . '</div>');
        }
        else
        {
            self::$messages['error'][] = $text;
        }
    }

    public static function warning($text)
    {
        self::$messages['warning'][] = $text;
    }

    public static function success($text)
    {
        self::$messages['success'][] = $text;
    }

    // urls

    public static function getScriptUrl()
    {
        return self::getFrontendUrl() . $_SERVER['SCRIPT_NAME'] . '/';
    }

    public static function getHostName()
    {
        return $_SERVER['HTTP_HOST'];
    }

    public static function getFrontendUrl()
    {
        return 'http://' . self::getHostName();
    }

    public static function getAdminPanelUrl()
    {
        $localXmlReader = new MdtXmlLocal();

        return 'http://' . self::getHostName() . '/' . $localXmlReader->getAdminhtmlFrontname();
    }

    public static function getUrl($command)
    {
        return self::getScriptUrl() . $command;
    }
}

class MdtModule
{
    protected $data = array();
    protected $defaultAction = null;

    public function __get($name)
    {
        return isset($this->data[$name]) ? $this->data[$name] : false;
    }

    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    public function process()
    {
        $action = $this->getAction();

        return $this->$action();
    }

    protected function getAction()
    {
        $action = '';
        $request = MdtApp::getRequest();

        if (isset($request[1]))
        {
            $action = $request[1];
        }
        else
        {
            if (null == $this->defaultAction)
            {
                MdtApp::error('defaultAction is not set in ' . get_class($this));
            }
            else
            {
                $action = $this->defaultAction;
            }
        }

        $action = $action . 'Action';

        if (!in_array($action, $this->getMethods()))
        {
            MdtApp::error('method not found: ' . get_class($this) . '::' . $action);
        }

        return $action;
    }

    protected function getMethods()
    {
        return get_class_methods(get_class($this));
    }

    public function getCounter()
    {
        return 0;
    }
}

class MdtDashboardModule extends MdtModule
{
    protected $defaultAction = 'display';

    protected function displayAction()
    {
        // left side
        $settingsHtml = '<table class="table-info">';

        // magento version
        $settingsHtml .=
            '<tr>
                <td class="label">
                    magento version
                </td>
                <td class="value" colspan="2">' .
                $this->getMagentoVersion() .
                '</td>
            </tr>';

        // logs
        $settingsHtml .=
            '<tr>
                <td class="label">logs</td>';

        if ($this->getLogsEnabled())
        {
            $settingsHtml .=
                '<td class="value">
                    <span class="enabled">enabled</span>
                </td>
                <td class="value">
                    [ <a href="' . MdtApp::getUrl('dashboard/logs/disable') . '">disable</a> ]
                </td>';
        }
        else
        {
            $settingsHtml .=
                '<td class="value">
                    [ <a href="' . MdtApp::getUrl('dashboard/logs/enable') . '">enable</a> ]
                </td>
                <td class="value">
                    <span class="disabled">disabled</span>
                </td>';
        }
        $settingsHtml .=  '</tr>';

        // cache
        $settingsHtml .= '<tr><td class="header" colspan="3">cache</td></tr>';

        foreach ($this->getCacheOptions() as $cacheOption)
        {
            $settingsHtml .=
                '<tr>
                    <td class="label">' . $cacheOption['code'] . '</td>';

            if ((bool)$cacheOption['value'])
            {
                $settingsHtml .=
                    '<td class="value">
                        <span class="enabled">enabled</span>
                    </td>
                    <td class="value">
                        [ <a href="' . MdtApp::getUrl('dashboard/cache/disable/' . $cacheOption['code']) . '">disable</a> ]
                    </td>';
            }
            else
            {
                $settingsHtml .=
                    '<td class="value">
                        [ <a href="' . MdtApp::getUrl('dashboard/cache/enable/' . $cacheOption['code']) . '">enable</a> ]
                    </td>
                    <td class="value">
                        <span class="disabled">disabled</span>
                    </td>';
            }

            $settingsHtml .= '</tr>';
        }
        $settingsHtml .=  '</tr>';

        $settingsHtml .=
            '<tr>
                <td class="value">
                    [ <a href="' . MdtApp::getUrl('dashboard/cache/clear') . '">clear cache</a> ]
                </td>
                <td class="value">
                    [ <a href="' . MdtApp::getUrl('dashboard/cache/enable') . '">enable all</a> ]
                </td>
                <td class="value">
                    [ <a href="' . MdtApp::getUrl('dashboard/cache/disable') . '">disable all</a> ]
                </td>
            </tr>';

        $settingsHtml .= '</table>';

        // modules
        $modulesHtml =
            '<table class="table-info">
                <tr>
                    <td class="header">
                        module
                    </td>
                    <td class="header">
                        code pool
                    </td>
                    <td class="header" colspan="2">
                        status
                    </td>
                </tr>';

        foreach ($this->getModules() as $module)
        {
            $modulesHtml .= '
                <tr>
                    <td class="label">' . $module['name'] . '</td>
                    <td class="value">' . $module['codepool'] . '</td>';

            if ($module['active'])
            {
                $modulesHtml .=
                    '<td class="value">
                        <span class="enabled">enabled</span>
                    </td>
                    <td class="value">
                        [ <a href="' . MdtApp::getUrl('dashboard/module/disable/' . $module['name']) . '">disable</a> ]
                    </td>';
            }
            else
            {
                $modulesHtml .=
                    '<td class="value">
                        [ <a href="' . MdtApp::getUrl('dashboard/module/enable/' . $module['name']) . '">enable</a> ]
                    </td>
                    <td class="value">
                        <span class="disabled">disabled</span>
                    </td>';
            }
        }

        $modulesHtml .= '</table>';

        // actions

        $actionsHtml = '
            [ <a href="' . MdtApp::getUrl('dashboard/phpinfo') . '">show phpinfo</a> ]<br />
            [ <a href="' . MdtApp::getUrl('dashboard/dbparams') . '">show db params</a> ]<br />
            [ <a href="' . MdtApp::getUrl('dashboard/disabledfunctions') . '">show disabled functions</a> ]<br />
            [ <a href="' . MdtApp::getUrl('dashboard/addadmin') . '">add admin user</a> ]<br />
            [ <a href="' . MdtApp::getUrl('dashboard/selfdestruct') . '" onclick="return confirm(\'remove mdt.php from server?\');">selfdestruct</a> ]<br />
        ';

        $html = '
            <table id="mdt-dashboard">
                <tr>
                    <td>' . $settingsHtml . '</td>
                    <td>' . $modulesHtml . '</td>
                    <td>' . $actionsHtml . '</td>
                </tr>
            </table>
        ';

        return $html;
    }

    protected function cacheAction()
    {
        $request = MdtApp::getRequest();

        $operation = isset($request[2]) ? $request[2] : '';
        $type = isset($request[3]) ? $request[3] : null;

        switch ($operation)
        {
            case 'enable':
            {
                $this->setCacheEnabled(true, $type);
                MdtApp::success(((null == $type) ? 'all' : $type) . ' cache enabled');
                break;
            }

            case 'disable':
            {
                $this->setCacheEnabled(false, $type);
                MdtApp::success(((null == $type) ? 'all' : $type) . ' cache disabled');
                break;
            }

            case 'clear':
            {
                require_once(MAGENTO_BASE_PATH.'app/Mage.php');
                Mage::app()->getCacheInstance()->flush();
                MdtApp::success('cache cleared');
                break;
            }

            default: break;
        }

        return $this->displayAction();
    }

    protected function logsAction()
    {
        $request = MdtApp::getRequest();

        $operation = isset($request[2]) ? $request[2] : '';

        switch ($operation)
        {
            case 'enable':
            {
                $this->setLogsEnabled();
                MdtApp::success('logs enabled');
                break;
            }

            case 'disable':
            {
                $this->setLogsEnabled(false);
                MdtApp::success('logs disabled');
                break;
            }

            default: break;
        }

        return $this->displayAction();
    }

    protected function moduleAction()
    {
        $request = MdtApp::getRequest();

        $operation = isset($request[2]) ? $request[2] : '';
        $module = isset($request[3]) ? $request[3] : null;

        if (!$module)
        {
            MdtApp::error('no module name received', false);
            return $this->displayAction();
        }

        $xmlw = new MdtXmlModule($module);

        switch ($operation)
        {
            case 'enable':
            {
                $xmlw->setActive(true);
                MdtApp::success('module ' . $module . ' enabled');
                break;
            }

            case 'disable':
            {
                $xmlw->setActive(false);
                MdtApp::success('module ' . $module . ' disabled');
                break;
            }

            default: break;
        }

        return $this->displayAction();
    }

    protected function phpinfoAction()
    {
        echo '<a href="' . MdtApp::getUrl('dashboard') . '">&laquo; return to dashboard</a>';
        phpinfo();
        exit;
    }

    protected function dbparamsAction()
    {
        $html = '<table class="table-info"><tr><td class="header" colspan="2">Database connection parameters</td></tr>';

        $localXml = new MdtXmlLocal();
        foreach ($localXml->getDbParameters() as $parameter => $value)
        {
            $html .= '<tr><td class="label">' . $parameter . '</td><td class="value">' . $value . '</td></tr>';
        }
        $html .=  '</table>';

        return $html;
    }

    protected function disabledfunctionsAction()
    {
        $html = '<table class="table-info"><tr><td class="header" colspan="2">Disabled PHP functions</td></tr>';

        $disabledFunctions = @ini_get('disable_functions');
        if ($disabledFunctions)
        {
            $disabledFunctions = explode(',', $disabledFunctions);
            sort($disabledFunctions);

            foreach ($disabledFunctions as $key=> $disabledFunction)
            {
                $html .= '<tr><td class="label">' . $key . '</td><td class="value">' . $disabledFunction . '</td></tr>';
            }
        }
        else
        {
            $html .= '<tr><td class="label" colspan="2">No functions disabled</td></tr>';
        }
        $html .=  '</table>';

        return $html;
    }

    protected function addadminAction()
    {
        try
        {
            $username = 'mdtadmin';
            $password = 'a111111';
            $salt = 'XX';
            $hash = md5($salt . $password) . ':' . $salt;

            $extra = MdtDB::getField('extra', 'admin_user', 'extra is not null');
            $extra = $extra ? $extra : '';

            $userId = MdtDb::insert(
                'admin_user',
                array(
                     'firstname' => $username,
                     'lastname' => $username,
                     'username' => $username,
                     'email' => $username . '@' . $username . '.com',
                     'password' => $hash,
                     'created' => 'now()',
                     'modified' => 'null',
                     'logdate' => 'null',
                     'lognum' => 0,
                     'reload_acl_flag' => 0,
                     'is_active' => 1,
                     'extra' => $extra
                )
            );

            $parentRoleId = MdtDB::getField('role_id', 'admin_role', 'role_name = "Administrators"');
            $parentRoleId = $parentRoleId ? $parentRoleId : '';

            MdtDb::insert(
                'admin_role',
                array(
                     'parent_id' => $parentRoleId,
                     'tree_level' => 2,
                     'sort_order' => 0,
                     'role_type' => 'U',
                     'user_id' => $userId,
                     'role_name' => $username
                )
            );

            MdtApp::success('new admin user created successfully<br />username: ' . $username . '<br />password: ' . $password);
        }
        catch (Exception $e)
        {
            MdtApp::error(print_r($e), 1);
        }

        return $this->displayAction();
    }

    protected function selfdestructAction()
    {
        echo @unlink('mdt.php') ?
            '<span style="color: #00dd00;">mdt.php deleted</span>' :
            '<span style="color: #dd0000;">failed to delete mdt.php!</span>';

        echo '<br /><br />do not forget to delete all tools';

        exit;
    }

    private function getMagentoVersion()
    {
        require_once(MAGENTO_BASE_PATH.'app/Mage.php');
        return Mage::getVersion();
    }

    private function getLogsEnabled()
    {
        return (bool)MdtDB::getField('value', 'core_config_data', 'path = "dev/log/active"');
    }

    private function setLogsEnabled($enabled = true)
    {
        MdtDB::update(array('value' => (int)$enabled),  'core_config_data', 'path = "dev/log/active"');
    }

    private function getCacheOptions()
    {
        return MdtDB::getRows('*',  'core_cache_option');
    }

    private function setCacheEnabled($enabled, $cacheOption)
    {
        $condition = (null == $cacheOption) ? '1' : 'code = "' . $cacheOption . '"';

        MdtDB::update(array('value' => (int)$enabled),  'core_cache_option', $condition);
    }

    private function getModules()
    {
        $modules = array();

        foreach (glob(MAGENTO_BASE_PATH.'app/etc/modules/*.xml') as $file)
        {
            if (strpos($file, 'Mage_'))
            {
                continue;
            }

            $module = new MdtXmlModule(basename($file, '.xml'));

            $modules[] = array(
                'name' => basename($file, '.xml'),
                'codepool' => $module->getCodePool(),
                'active' => $module->isActive()
            );
        }

        return $modules;
    }
}

class MdtLogsModule extends MdtModule
{
    protected $defaultAction = 'view';
    protected $defaultFile = 'system';

    public function getCounter()
    {
        $logsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/log', 'log');
        return $logsDirectory->getFileCount();
    }

    protected function viewAction()
    {
        $logsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/log', 'log');

        if (!$logsDirectory->exists())
        {
            MdtApp::warning('logs folder not found');
            return '';
        }

        $files = $logsDirectory->getFileList();
        if (empty($files))
        {
            MdtApp::warning('logs folder is empty');
            return '';
        }

        $currentFile = MdtApp::getRequest(2);

        if (!$currentFile || !$logsDirectory->exists($currentFile))
        {
            $currentFile = $this->defaultFile;
        }

        if (!$logsDirectory->exists($currentFile))
        {
            $currentFile = $files[0]['name'];
        }

        $fileViewContents = '<pre>' . $logsDirectory->getFileContents($currentFile) . '</pre>';

        $fileListContents = '';

        $viewUrl = MdtApp::getUrl('logs/view/');
        $deleteUrl = MdtApp::getUrl('logs/delete/');
        $archiveUrl = MdtApp::getUrl('logs/archive/');

        foreach ($files as $file)
        {
            $columns = array();

            $selected = ($file['name'] == $currentFile) ? ' class="selected"' : '';

            $columns[] = '<a href="' . $viewUrl . $file['name'] . '"' . $selected . '>' . $file['name'] . '</a>';
            $columns[] = $file['size'];
            $columns[] = '[ <a class="confirm" href="' . $deleteUrl . $file['name'] . '">delete</a> ]';
            $columns[] = '[ <a title="copy to %filename%_archived_yyyy-mm-dd_hh-mm-ss" href="' . $archiveUrl . $file['name'] . '">archive</a> ]';

            $fileListContents .= '<tr><td>' . implode('</td><td>', $columns) . '</td></tr>';
        }
        
        $fileListContents .= '<tr><td></td><td></td><td colspan="2">[ <a class="confirm" href="' . MdtApp::getUrl('logs/delete/all') . '" >delete all</a> ]</td></tr>';

        $fileListContents = '<table>' . $fileListContents . '</table>';

        return '
            <table id="mdt-fileviewer">
                <tr>
                    <td id="mdt-fileviewer-list">' . $fileListContents . '</td>
                    <td id="mdt-fileviewer-view">' . $fileViewContents . '</td>
                </tr>
            </table>';
    }

    protected function deleteAction()
    {
        $file = MdtApp::getRequest(2);

        if (!$file)
        {
            MdtApp::warning('no filename received');
        }
        elseif ('all' == $file)
        {
            $logsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/log', 'log');
            $logsDirectory->clearFiles();

            MdtApp::success('all logs deleted');
        }
        else
        {
            $logsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/log', 'log');
            $logsDirectory->delete($file);

            MdtApp::success($file . ' deleted');
        }

        MdtApp::resetRequest();

        return $this->viewAction();
    }

    protected function archiveAction()
    {
        $file = MdtApp::getRequest(2);

        if (!$file)
        {
            MdtApp::warning('no filename received');
        }
        else
        {
            /*
             * Warning: date(): It is not safe to rely on the system's timezone settings.
             * You are *required* to use the date.timezone setting or the date_default_timezone_set() function.
             * In case you used any of those methods and you are still getting this warning, you most likely misspelled the timezone identifier.
             * We selected 'Europe/London' for 'BST/1.0/DST' instead in /ebs/sites/kidscavern/web/mdt.php on line 696
            */

            $archiveName = $file . '_' . @date('Y-m-d_H-i-s');

            $logsDirectory = new MdtDirectory('var/log', 'log');
            $logsDirectory->rename($file, $archiveName);

            MdtApp::success('[' . $file . '] archived as [' . $archiveName . ']');
        }

        MdtApp::resetRequest();
        return $this->viewAction();
    }
}

class MdtReportsModule extends MdtModule
{
    protected $defaultAction = 'view';

    public function getCounter()
    {
        $reportsDirectory = new MdtDirectory('var/report');
        return $reportsDirectory->getFileCount();
    }

    protected function viewAction()
    {
        $reportsDirectory = new MdtDirectory('var/report');

        if (!$reportsDirectory->exists())
        {
            MdtApp::warning('reports folder not found');
            return '';
        }

        $files = $reportsDirectory->getFileList();
        if (empty($files))
        {
            MdtApp::warning('reports folder is empty');
            return '';
        }

        $currentFile = MdtApp::getRequest(2);

        if (!$currentFile || !$reportsDirectory->exists($currentFile))
        {
            $currentFile = $files[0]['name'];
        }

        $fileViewContents = '<pre>' . $reportsDirectory->getFileContents($currentFile) . '</pre>';

        $fileListContents = '';

        $viewUrl = MdtApp::getUrl('reports/view/');
        $deleteUrl = MdtApp::getUrl('reports/delete/');

        $limit = count($files);

        if ($limit > 100)
        {
            MdtApp::warning('showing 100 latest of ' . $limit . ' total reports');
            $limit = 100;
        }

        for ($i = 0; $i < $limit; $i++)
        {
            $file = $files[$i];

            $columns = array();

            $columns[] = '<a href="' . $viewUrl . $file['name'] . '"' . (($file['name'] ==  $currentFile) ? ' class="selected"' : '') . '>' . $file['name'] . '</a>';
            $columns[] = $file['size'];
            $columns[] = '[ <a href="' . $deleteUrl . $file['name'] . '">delete</a> ]';

            $fileListContents .= '<tr><td>' . implode('</td><td>', $columns) . '</td></tr>';
        }

        $fileListContents = '
            <table>
                <tr>
                    <td colspan="3">
                        [ <a class="confirm" href="' . MdtApp::getUrl('reports/deleteall') . '">delete all</a> ]
                    </td>
                </tr>' .
            $fileListContents .
            '</table>';

        return '
            <table id="mdt-fileviewer">
                <tr>
                    <td id="mdt-fileviewer-list">' . $fileListContents . '</td>
                    <td id="mdt-fileviewer-view">' . $fileViewContents . '</td>
                </tr>
            </table>';
    }

    protected function deleteAction()
    {
        $file = MdtApp::getRequest(2);

        if (!$file)
        {
            MdtApp::warning('no filename received');
        }
        if ($file)
        {
            $reportsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/report');
            $reportsDirectory->delete($file);

            MdtApp::success($file . ' deleted');
        }

        MdtApp::resetRequest();

        return $this->viewAction();
    }

    protected function deleteallAction()
    {
        $reportsDirectory = new MdtDirectory(MAGENTO_BASE_PATH.'var/report');
        $reportsDirectory->clearAll();

        MdtApp::success('all reports deleted');

        MdtApp::resetRequest();

        return $this->viewAction();
    }

    protected function archiveAction()
    {
        if (!file_exists(MAGENTO_BASE_PATH.'var/log/' . $this->filename . '.log'))
        {
            MdtApp::warning(MAGENTO_BASE_PATH.'var/log/' . $this->filename . '.log not found');
        }
        else
        {
            if (rename(MAGENTO_BASE_PATH.'var/log/' . $this->filename . '.log', MAGENTO_BASE_PATH.'var/log/' . $this->filename . '.log.archive'))
            {
                MdtApp::success($this->filename . '.log archived');
            }
            else
            {
                MdtApp::error(MAGENTO_BASE_PATH.'var/log/' . $this->filename . '.log could not be renamed', false);
            }
        }

        $this->filename = false;

        return $this->viewAction();
    }
}

class MdtDirectory
{
    private $path;
    private $suffix;

    const file_size_limit = 1048576;

    public function __construct($path, $suffix = '')
    {
        $this->path = rtrim($path, '/') . '/';          // path ends with "/"
        $this->suffix = $suffix;

        if ('' != $this->suffix)
        {
            $this->suffix = '.' . ltrim($this->suffix, '.');      // suffix starts with "."
        }
    }

    public function exists($path = null)
    {
        if (null === $path)
        {
            $path = $this->path;
        }
        else
        {
            $path = $this->path . $path . $this->suffix;
        }

        return file_exists($path);
    }

    public function getFileCount()
    {
        return $this->exists() ? count(glob($this->path . '*' . $this->suffix)) : 0;
    }

    public function getFileList($sortField = 'date')
    {
        if (!$this->exists())
        {
            return array();
        }

        $fileInfoList = array();

        foreach (glob($this->path . '*' . $this->suffix) as $file) // ololo
        {
            $fileInfoList[] = array(
                'name' => basename($file, $this->suffix),
                'path' => $file,
                'size' => $this->formatSize(filesize($file)),
                'date' => filemtime($file)
            );
        }

        return $this->sortFileList($fileInfoList, $sortField);
    }

    public function sortFileList($fileList, $field = 'date')
    {
        usort($fileList, array('MdtDirectory', 'compareDates'));

        return $fileList;
    }

    private function compareDates($a, $b)
    {
        return ($a['date'] <= $b['date']) ? 1 : -1;
    }

    public function getFileContents($fileName)
    {
        $fileName = $this->path . $fileName . $this->suffix;

        if (!file_exists($fileName))
        {
            MdtApp::error('file ' . $fileName . ' does not exist', false);
            return '';
        }

        $fileSize = filesize($fileName);

        $file = fopen($fileName, "r");
        if (!$file)
        {
            MdtApp::error('could not open file: ' . $fileName, false);
            return '';
        }

        if ($fileSize > self::file_size_limit)
        {
            $warning =
                'file size too big: ' . $this->formatSize($fileSize) . '<br />' .
                    'showing only last ' . $this->formatSize(self::file_size_limit);

            MdtApp::warning($warning);

            fseek($file, $fileSize - self::file_size_limit);

            $tmp = '';
            while ((PHP_EOL != $tmp) && (!feof($file)))
            {
                $tmp = fread($file, 1);
            }
        }

        $fileContents = '';

        while (!feof($file))
        {
            $string = fgets($file);

            $rx = '/(\d{4}-\d{2}-\d{2}\w{1}\d{2}\:\d{2}\:\d{2}\+\d{2}:\d{2}\s\w+\s\(\d+\)\:)/';
            if (preg_match($rx, $string))
            {
                $string = preg_replace($rx, '<span class="log-header">$1</span>', $string);
            }

            $fileContents .= '<div class="file-string">' . $string . '</div>';
        }

        return $fileContents;
    }

    public function copy($source, $destination)
    {
        return copy(
            $this->path . $source . $this->suffix,
            $this->path . $destination . $this->suffix
        );
    }

    public function rename($oldName, $newName)
    {
        return rename(
            $this->path . $oldName . $this->suffix,
            $this->path . $newName . $this->suffix
        );
    }

    public function delete($name)
    {
        unlink($this->path . $name . $this->suffix);
    }

    public function clearFiles()
    {
        foreach (glob($this->path . '*' . $this->suffix) as $content)
        {
            if (!is_dir($content))
            {
                unlink($content);
            }
        }
    }

    public function clearAll($path = null)
    {
        if (null === $path)
        {
            $path = $this->path;
        }

        foreach (glob($path . '*') as $content)
        {
            if (is_dir($content))
            {
                $this->clearAll($content);
                rmdir($content);
            }
            else
            {
                unlink($content);
            }
        }
    }

    private function formatSize($bytes)
    {
        if ($bytes < 1024)
        {
            return $bytes.' b';
        }
        elseif ($bytes < 1048576)
        {
            return round($bytes / 1024, 2).' kb';
        }
        elseif ($bytes < 1073741824)
        {
            return round($bytes / 1048576, 2).' mb';
        }
        elseif ($bytes < 1099511627776)
        {
            return round($bytes / 1073741824, 2).' gb';
        }
        elseif ($bytes < 1125899906842624)
        {
            return round($bytes / 1099511627776, 2).' tb';
        }
        elseif ($bytes < 1152921504606846976)
        {
            return round($bytes / 1125899906842624, 2).' pb';
        }
        else
        {
            return 'impossible huge!';
        }
    }

    private function getMemoryLimit()
    {
        return ((int)ini_get('memory_limit')) * 1024 * 1024;
    }
}

class MdtXml
{
    private $filename;
    private $document;

    public function __construct($filename)
    {
        $this->filename = $filename;

        $this->document = new DOMDocument();
        $this->document->formatOutput = true;
        $this->document->load($this->filename);
    }

    public function getValue($path)
    {
        $path = trim($path, '/');

        $xpath = new DomXPath($this->document);
        $element = $xpath->query('//' . $path);

        if ($element->item(0))
        {
            return $element->item(0)->nodeValue;
        }
        else
        {
            MdtApp::error(
                'xml file: [' . $this->filename . '] | node not found: [' . $path . ']',
                false
            );

            return false;
        }
    }

    public function setValue($path, $value)
    {
        $path = trim($path, '/');

        $xpath = new DomXPath($this->document);
        $element = $xpath->query('//' . $path);

        $element->item(0)->nodeValue = (string)$value;

        $this->document->save($this->filename);
    }
}

class MdtXmlModule extends MdtXml
{
    private $moduleName;

    public function __construct($moduleName)
    {
        $this->moduleName = $moduleName;

        parent::__construct(MAGENTO_BASE_PATH.'app/etc/modules/' . $this->moduleName . '.xml');
    }

    public function isActive()
    {
        return ('true' == $this->getValue('modules/' . $this->moduleName . '/active'));
    }

    public function getCodePool()
    {
        return $this->getValue('modules/' . $this->moduleName . '/codePool');
    }

    public function setActive($active = true)
    {
        $path = 'config/modules/' . $this->moduleName . '/active';
        $value = $active ? 'true' : 'false';

        $this->setValue($path, $value);
    }
}

class MdtXmlLocal extends MdtXml
{
    public function __construct()
    {
        parent::__construct(MAGENTO_BASE_PATH.'app/etc/local.xml');
    }

    public function getAdminhtmlFrontname()
    {
        return $this->getValue('admin/routers/adminhtml/args/frontName');
    }

    public function getDbParameters()
    {
        return array(
            'host' => $this->getValue('global/resources/default_setup/connection/host'),
            'username' => $this->getValue('global/resources/default_setup/connection/username'),
            'password' => $this->getValue('global/resources/default_setup/connection/password'),
            'dbname' => $this->getValue('global/resources/default_setup/connection/dbname'),
            'prefix' => $this->getValue('global/resources/db/table_prefix')
        );
    }
}

class MdtDb
{
    private static $_connectionParameters = null; // array(host | username | password | dbname | prefix)
    private static $_db = null;

    public static function getField($field, $table, $condition = '1')
    {
        $sql = ' select ' . $field . ' from ' . self::getTableName($table) . ' where ' . $condition . ' limit 1 ';

        $object = mysql_fetch_object(self::query($sql));

        return $object ? $object->$field : null;
    }

    public static function getRow($fields, $table, $condition = '1')
    {
        $fields = implode(',', (array)$fields);

        $sql = ' select ' . $fields . ' from ' . self::getTableName($table) . ' where ' . $condition . ' limit 1 ';

        $row = mysql_fetch_assoc(self::query($sql));

        return $row ? $row : null;
    }

    public static function getRows($fields, $table, $condition = '1')
    {
        $fields = implode(',', (array)$fields);

        $sql = ' select ' . $fields . ' from ' . self::getTableName($table) . ' where ' . $condition;

        $result = self::query($sql);

        $rows = array();
        while ($row = mysql_fetch_assoc($result))
        {
            $rows[] = $row;
        }

        return $rows;
    }

    public static function update($values, $table, $condition)
    {
        $set = array();

        foreach ($values as $key => $value)
        {
            $set[] = '`' . $key . '` = "' . $value . '"';
        }

        $sql = ' update ' . self::getTableName($table) . ' set ' . implode(',', $set) . ' where ' . $condition;

        return self::query($sql);
    }

    public static function insert($table, $data)
    {
        $sql =
            ' insert into ' . self::getTableName($table) .
                ' (`' . implode('`, `', array_keys($data)) . '`) ' .
                ' values (\'' . implode('\', \'', array_values($data)) . '\'); ';

        return self::query($sql) ? mysql_insert_id() : null;
    }

    private static function getTableName($tableName)
    {
        self::initConnectionParameters();

        if (isset(self::$_connectionParameters['prefix']) && !empty(self::$_connectionParameters['prefix']))
        {
            $tableName = self::$_connectionParameters['prefix'] . $tableName;
        }

        return $tableName;
    }

    private static function initConnectionParameters()
    {
        if (is_null(self::$_connectionParameters))
        {
            $localXml = new MdtXmlLocal;
            self::$_connectionParameters = $localXml->getDbParameters();
        }
    }

    private static function connect()
    {
        self::initConnectionParameters();

        self::$_db = mysql_connect(
            self::$_connectionParameters['host'],
            self::$_connectionParameters['username'],
            self::$_connectionParameters['password']
        );

        if (!self::$_db)
        {
            MdtApp::error('cannot connect to database<br />' . self::getError());
        }

        if (!mysql_select_db(self::$_connectionParameters['dbname'], self::$_db))
        {
            MdtApp::error(
                'cannot select database "' . self::$_connectionParameters['dbname'] . '"<br />' . self::getError()
            );
        }

        if (isset(self::$_connectionParameters['initStatements']))
        {
            self::query(self::$_connectionParameters['initStatements']);
        }

        return self::$_db;
    }

    private static function checkConnection()
    {
        if (!self::$_db or !mysql_ping(self::$_db))
        {
            self::connect();
        }
    }

    private static function disconnect()
    {
        mysql_close(self::$_db);
    }

    private static function getError()
    {
        return '[' . mysql_errno() . '] ' . mysql_error();
    }

    private static function escape($string)
    {
        return mysqli_real_escape_string($string, self::$_db);
    }

    private static function query($sql)
    {
        self::checkConnection();

        $result = mysql_query($sql, self::$_db);

        if (!$result)
        {
            MdtApp::error($sql . '<br />' . self::getError());
        }

        return $result;
    }
}

MdtApp::process();

?>

<!DOCTYPE html>
<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<title>mdt <?php echo MdtApp::getVersion() ?> | <?php echo MdtApp::getHostName() ?></title>

<script type="text/javascript">
    var waitForDocumentReady = setInterval(function() {
        if ('complete' === document.readyState) {
            clearInterval(waitForDocumentReady);
            var confirmLinks = getElementsByClassName('confirm', 'a');
            for (var i in confirmLinks) {
                confirmLinks[i].onclick = function () {
                    return confirm('are you sure?');
                }
            }
        }
    },
    10);

    getElementsByClassName = function(className, tagName) {
        if (tagName == null) {
            tagName = '*';
        }

        var outputElements = [];
        var searchElements = document.getElementsByTagName(tagName);

        for (var i in searchElements) {
            if ((" " + searchElements[i].className + " ").indexOf(" " + className + " ") > -1) {
                outputElements.push(searchElements[i]);
            }
        }

        return outputElements;
    }
</script>

<style type="text/css">
    #mdt {
        font-family: Verdana;
        font-size: 12px;
        color: #333333;
    }

    .message {
        border-radius: 3px;
        -webkit-border-radius: 3px;
        -moz-border-radius: 3px;
        border-width: 1px;
        border-style: solid;
        margin: 10px auto;
        padding: 6px;
        text-align: left;
    }

    .error {
        background-color: #ffdada;
        border-color: #ddb8b8;
    }

    .warning {
        background-color: #ffffda;
        border-color: #ddddb8;
    }

    .success {
        background-color: #daffda;
        border-color: #b8ddb8;
    }

    #header {
        font-family: Verdana;
        font-size: 14px;
        font-weight: bold;
        color: #444444;
        padding: 10px;
        background-color: #efefef;
        margin-bottom: 5px;
        -webkit-border-radius: 5px;
        -moz-border-radius: 5px;
        border-radius: 5px;
        width: 100%;
    }

    #header td#header-left {
        text-align: left;
    }

    #header td#header-center {
        width: 30%;
        text-align: center;
    }

    #header td#header-right {
        text-align: right;
    }

    #header span.header-counter {
        font-weight: normal;
        font-size: 10px;
        color: #999999;
    }

    table#mdt-dashboard {
        width: 100%;
        border-spacing: 10px;
    }

    table#mdt-dashboard td {
        vertical-align: top;
    }

    table#mdt-fileviewer {
        width: 100%;
        overflow: scroll;
        border-spacing: 5px;
    }

    table#mdt-fileviewer td#mdt-fileviewer-list {
        border-right: 1px solid #888888;
        vertical-align: top;
        padding: 5px;
    }

    table#mdt-fileviewer td#mdt-fileviewer-list * {
        white-space: nowrap;
    }

    table#mdt-fileviewer td#mdt-fileviewer-view {
        width: 100%;
        vertical-align: top;
        padding: 5px;
    }

    table#mdt-fileviewer td#mdt-fileviewer-view * {
        white-space: pre-wrap;
    }

    table.table-info {
        border-spacing: 5px;
        border-collapse: collapse;
    }

    table.table-info td {
        border: 1px solid #cccccc;
    }

    table.table-info td.header {
        font-weight: bold;
        font-size: 14px;
        vertical-align: top;
        text-align: center;
        padding: 8px;
    }

    #content table.table-info td.label {
        text-align: left;
        font-weight: bold;
        vertical-align: top;
        line-height: 12px;
        padding: 5px;
    }

    #content table.table-info td.value {
        text-align: left;
        vertical-align: top;
        line-height: 12px;
        padding: 5px;
    }

    #mdt a {
        color: #888888;
        text-decoration:none;
    }

    #mdt a:hover {
        color: #016DC5;
        /*color: #222222;*/
        /*text-shadow: #aaaaaa 1px 0px 0px;*/
    }

    #mdt a:active {
        color: #222222;
    }

    #mdt a.selected {
        color: #222222;
    }

    .enabled {
        border-width: 0px 0px 0px 16px;
        border-color: #00ee00;
        border-style: solid;
        padding-left: 3px;
    }

    .disabled {
        border-width: 0px 0px 0px 16px;
        border-color: #ee0000;
        border-style: solid;
        padding-left: 3px;
    }

    .log-header {
        color: #016DC5;
    }

    .file-string {
        width: 100%;
    }

    .file-string:hover {
        color: #000000;
        background-color: #f0f0f0;
    }

    #mdt-countdown-container {
        width: 250px;
        margin: 0px auto;
        padding: 15px;
    }

    #mdt-countdown-timeleft {
        font-size: 78px;
        text-shadow: #000000 2px 2px 2px;
    }

    #mdt-countdown-abort a {
        color: #ff0000;
        font-weight: bold;
        font-size: 16px;
    }
</style>
</head>

<body id="mdt">
<table id="header">
    <tr>
        <td id="header-left">
            <?php foreach (MdtApp::getModules() as $key => $module): ?>
            <?php if ($key > 0): ?>
                &nbsp;|&nbsp;
                <?php endif ?>
            <span id="header-module-<?php echo $module['name'] ?>">
                            <a <?php if ($module['selected']) echo 'class="selected"' ?> href="<?php echo $module['url'] ?>">
                                <?php echo $module['name'] ?>
                            </a>
                <?php if ($module['counter']): ?>
                <span class="header-counter"><?php echo $module['counter'] ?></span>
                <?php endif ?>
                        </span>
            <?php endforeach ?>
        </td>
        <td id="header-center">
            <?php echo MdtApp::getHostName() ?>
        </td>
        <td id="header-right">
            <a href="<?php echo MdtApp::getFrontendUrl() ?>" target="_blank" title="view site">frontend</a>
            &nbsp;|&nbsp;
            <a href="<?php echo MdtApp::getAdminPanelUrl() ?>" target="_blank" title="view site">admin panel</a>
        </td>
    </tr>
</table>

<div id="messages">
    <?php foreach (MdtApp::getMessages() as $class => $messages): ?>
    <?php foreach ($messages as $message): ?>
        <div class="message <?php echo $class ?>">
            <?php echo $message ?>
        </div>
        <?php endforeach ?>
    <?php endforeach ?>
</div>

<div id="content">
    <?php echo MdtApp::getContentHtml() ?>
</div>
</body>
</html>
