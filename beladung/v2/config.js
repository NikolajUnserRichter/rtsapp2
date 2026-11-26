/* GENERATED: endpoint block copied from beladung/app.js (first mask) by build_rtsapp2_masks.py.
   Change the endpoints there and rebuild. Optional per environment: statusRead (flow "Transportstatus lesen"). */
const RTS_ENV = /^28ade5d3/i.test(new URLSearchParams(window.location.search).get('env') || '') ? 'prod' : 'dev';
const ENDPOINTS = {
    dev: {
        auth: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/17/workflows/05f3abfc061845e5a32f218dae03a4c2/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=QbpMBZDp4Mo6HqUS6tXGIwNeZW41ikD0tOeDlyeqU3E',
        submit: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/18/workflows/2da33f7d32354e209c8ca5da3f36ad9f/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=2GptK-F0ZjIp22kh2gaieNxkN6Zj-bFVccdxtwCOsnE',
        statusRead: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/27/workflows/76b4344f0985420994f7e65ff4f8ba82/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=vxQumfcl-Sn83NESeIZvdkUpSoaqYj-XtSdviTZKdXw',
        reasons: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/13/workflows/399f2125490a4ad58c28dc3a0ed9b66e/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=LjmJb2brJ7KcU5mNuA10hi7S3xCunoz97fzfz2NYQ1k',
    },
    prod: {
        auth: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/08/workflows/35c2caca7ded4d9c9de850a53cc6b18c/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=yQXA9VOaBvgB7Brx6BpTCdPO7f9uTXl2Ye2PCQaUA5A',
        submit: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/10/workflows/52ba7f70aeea4a0cadf8cc7a42c886a9/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=JrJnsVwkJOqtD0g7VXpRIPHsfkBiltDfoL3gFDqo9FY',
        reasons: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/25/workflows/186260ce2b78432ba77d763d2430735e/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=5f2bQYqMhi2JP_WcTtVRIPL1DOBIR7SNIu5UlfESYZk',
    },
}[RTS_ENV];
