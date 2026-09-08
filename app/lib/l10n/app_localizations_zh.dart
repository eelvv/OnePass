// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Chinese (`zh`).
class AppLocalizationsZh extends AppLocalizations {
  AppLocalizationsZh([String locale = 'zh']) : super(locale);

  @override
  String get appTitle => 'OnePass';

  @override
  String get unlock => '解锁';

  @override
  String get unlockPrompt => '输入主密码';

  @override
  String get createVault => '创建密码库';

  @override
  String get createVaultPrompt => '设置库名称与主密码';

  @override
  String get vaultName => '库名称';

  @override
  String get masterPassword => '主密码';

  @override
  String get confirmPassword => '确认密码';

  @override
  String get passwordsDontMatch => '两次输入不一致';

  @override
  String get vaultNameHint => '我的密码库';

  @override
  String get wrongPassword => '密码错误';

  @override
  String get searchEntries => '搜索条目';

  @override
  String get noEntries => '还没有条目';

  @override
  String get noEntriesHint => '点击 + 添加第一条密码或 2FA 条目';

  @override
  String get noSearchResults => '没有匹配项';

  @override
  String get lock => '锁定';

  @override
  String get settings => '设置';

  @override
  String get addEntry => '添加条目';

  @override
  String get editEntry => '编辑条目';

  @override
  String get delete => '删除';

  @override
  String get deleteSelected => '删除所选';

  @override
  String deleteConfirm(int count) {
    return '删除选中的 $count 条条目？';
  }

  @override
  String get deleteEntryConfirm => '删除该条目？';

  @override
  String get cancel => '取消';

  @override
  String get save => '保存';

  @override
  String get saved => '已保存';

  @override
  String get copied => '已复制';

  @override
  String get importAction => '导入…';

  @override
  String get exportAction => '导出…';

  @override
  String get importPickFile => '选择文件（Aegis JSON / Google 迁移）';

  @override
  String get importPickUriText => '粘贴 otpauth:// 链接';

  @override
  String get importUriHint => '每行一条 otpauth:// 链接';

  @override
  String imported(int count) {
    return '已导入 $count 条';
  }

  @override
  String get importFailed => '导入失败';

  @override
  String get exportOtpauth => '2FA 导出为 otpauth:// 链接';

  @override
  String get exportAegis => '2FA 导出为 Aegis JSON';

  @override
  String get exportShared => '已导出（分享/复制）';

  @override
  String get entryType => '类型';

  @override
  String get typePassword => '密码';

  @override
  String get type2fa => '两步验证';

  @override
  String get fieldTitle => '标题';

  @override
  String get fieldUsername => '用户名';

  @override
  String get fieldPassword => '密码';

  @override
  String get fieldUrl => '网址';

  @override
  String get fieldNotes => '备注';

  @override
  String get fieldIssuer => '签发方';

  @override
  String get fieldAccount => '账户';

  @override
  String get fieldSecret => '密钥或 otpauth:// 链接';

  @override
  String get fieldKind => '类型';

  @override
  String get fieldAlgorithm => '算法';

  @override
  String get fieldDigits => '位数';

  @override
  String get fieldPeriod => '周期（秒）';

  @override
  String get fieldCounter => '计数器';

  @override
  String get fieldPin => 'PIN 码';

  @override
  String get generate => '生成';

  @override
  String get keepSecretHint => '留空表示保持当前密钥不变';

  @override
  String get requiredField => '必填';

  @override
  String get appearance => '外观';

  @override
  String get themeMode => '主题';

  @override
  String get themeSystem => '跟随系统';

  @override
  String get themeLight => '浅色';

  @override
  String get themeDark => '深色';

  @override
  String get accentColor => '强调色';

  @override
  String get language => '语言';

  @override
  String get langSystem => '跟随系统';

  @override
  String get security => '安全';

  @override
  String get lockOnBackground => '切后台时锁定';

  @override
  String get changeMasterPassword => '修改主密码';

  @override
  String get changePasswordHint => '立即生效并保存';

  @override
  String get passwordChanged => '主密码已修改';

  @override
  String get about => '关于';

  @override
  String get engineVersion => '引擎版本';

  @override
  String get locked => '已锁定';

  @override
  String get selectToDelete => '长按条目可多选删除';

  @override
  String get errorLoading => '加载失败';

  @override
  String get retry => '重试';

  @override
  String get otpCopied => '验证码已复制';

  @override
  String get errorGeneric => '操作失败';

  @override
  String get errorFileFormat => '该文件不是有效的密码库，或已损坏';

  @override
  String get errorIo => '文件读写失败';

  @override
  String get errorInvalidInput => '输入无效';

  @override
  String get importKdbx => '导入密码库（.kdbx）';

  @override
  String get exportKdbx => '导出密码库副本（.kdbx）';

  @override
  String get vaultImported => '密码库已导入';

  @override
  String get vaultPasswordPrompt => '输入该密码库的主密码';

  @override
  String get logs => '日志';

  @override
  String get logFile => '日志文件';

  @override
  String get shareLogs => '分享日志';

  @override
  String get clearLogs => '清空日志';

  @override
  String get logsCleared => '日志已清空';

  @override
  String get fieldCreated => '创建于';

  @override
  String get fieldModified => '修改于';
}
