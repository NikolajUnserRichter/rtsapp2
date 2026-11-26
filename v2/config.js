/* GENERATED: endpoint block copied from app.js (first mask) by build_rtsapp2_masks.py.
   Change the endpoints there and rebuild. Optional per environment: statusRead (flow "Transportstatus lesen"). */
const RTS_ENV = /^28ade5d3/i.test(new URLSearchParams(window.location.search).get('env') || '') ? 'prod' : 'dev';
const ENDPOINTS = {
    dev: {
        auth: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/17/workflows/05f3abfc061845e5a32f218dae03a4c2/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=QbpMBZDp4Mo6HqUS6tXGIwNeZW41ikD0tOeDlyeqU3E',
        submit: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/13/workflows/680f7172289e436180891d72163c9b59/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=nzN_tqLWUgnt2-WDIJd5YeLiAoygnbXfFDzspNiEyuA',
        statusRead: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/27/workflows/76b4344f0985420994f7e65ff4f8ba82/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=vxQumfcl-Sn83NESeIZvdkUpSoaqYj-XtSdviTZKdXw',
    },
    prod: {
        auth: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/08/workflows/35c2caca7ded4d9c9de850a53cc6b18c/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=yQXA9VOaBvgB7Brx6BpTCdPO7f9uTXl2Ye2PCQaUA5A',
        submit: 'https://28ade5d300a5e6ea8868bd488be7b8.49.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/21/workflows/b81d6ad31f0b483bbdcfc9ad8e883993/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=fnfOsg8Ldl2oouX_Gnj9zAUb3pAMA2IUrmET8UlyHnU',
    },
}[RTS_ENV];
