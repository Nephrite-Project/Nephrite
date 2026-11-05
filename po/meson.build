i18n = import('i18n')

if find_program('xgettext', required: get_option('gettext')).found()
  i18n.gettext('nephrite',
               args: '--msgid-bugs-address=https://github.com/Nephrite-Project/Nephrite/issues',
               preset: 'glib')
endif
