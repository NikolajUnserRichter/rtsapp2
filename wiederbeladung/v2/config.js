/* GENERATED: endpoint block copied from wiederbeladung/app.js (first mask) by build_rtsapp2_masks.py.
   Change the endpoints there and rebuild. Optional per environment: statusRead (flow "Transportstatus lesen"). */
const RTS_ENV = /^28ade5d3/i.test(new URLSearchParams(window.location.search).get('env') || '') ? 'prod' : 'dev';
const ENDPOINTS = {
    dev: {
        auth: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/17/workflows/05f3abfc061845e5a32f218dae03a4c2/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=QbpMBZDp4Mo6HqUS6tXGIwNeZW41ikD0tOeDlyeqU3E',
        submit: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/31/workflows/611c9b8e26eb4655b5d28a0614f261f4/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=muqlB7zKUV3Y8qvHh4FxqtTsIYDAIV__pjDT--cUaj8',
        reasons: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/13/workflows/399f2125490a4ad58c28dc3a0ed9b66e/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=LjmJb2brJ7KcU5mNuA10hi7S3xCunoz97fzfz2NYQ1k',
    },
    prod: {
        auth: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/08/workflows/35c2caca7ded4d9c9de850a53cc6b18c/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=yQXA9VOaBvgB7Brx6BpTCdPO7f9uTXl2Ye2PCQaUA5A',
        submit: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/04/workflows/603e5752231c415fabee797a7f07d691/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=FcBMjELEMM4_QMC_9InZZQ6KFTDbTEm-DbIrtD0a5P8',
        reasons: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/25/workflows/186260ce2b78432ba77d763d2430735e/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=5f2bQYqMhi2JP_WcTtVRIPL1DOBIR7SNIu5UlfESYZk',
    },
}[RTS_ENV];
