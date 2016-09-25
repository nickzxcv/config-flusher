configpath = '/pathtoflush/*'
configdir = '/directorytowatch'
configfile = 'file_in_watched_directory_to_trigger_flushing'
configurl = 'https://cdnorigin.example.com/check_here_origin_got_the_update'

failwaits = {
    'flush': 5,
    'versionmismatch': 1,
    'threadtimer': 30,
}

CDNconfig = {
    'Level3': {
        'apikeyid': '1234567890',  # <- config-flusher Level3 API user
        'apisecret': 'abcdef123455',
        'accessgroupid': '123',
        'scid': 'ABCDE12345',
        'propertyname': 'cdnresource.example.com',
    },

    'Edgecast': {
        'apitoken': 'fsafdsf1324-asf34-sadf35-asdfasf334234',  # <- config-flusher@example.com Edgecast API user
        'customernumber': '1234',
        'mediapathprefix': 'http://wac.1234.edgecastcdn.net/801234/cdnresource',
        'mediatype': '8',  # HTTP Small
    },

    'Cloudfront': {
        'accesskeyid': 'ABCDEFGHIJKL',  # <- config-flusher AWS IAM user
        'secretaccesskey': 'MNOPQRSTUVWXYZ',
        'distributionid': u'GHIJKLMNOPQRST',
    },
}
