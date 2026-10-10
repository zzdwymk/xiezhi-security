// Passive CDP capture for streams whose client releases the reader at the
// terminal event. Network.getResponseBody may discard these cancelled bodies.
// Captures only this app's AI response bytes; no credentials, request headers,
// browser storage, business API calls or response modification.
'use strict';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
module.exports.captureAiWire = async page => {
  const session = await page.context().newCDPSession(page);
  const records = new Map();
  session.on('Network.responseReceived', event => {
    if (!/\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(event.response.url)) return;
    const record={url:event.response.url,chunks:[],ready:false,ended:false,error:''};
    records.set(event.requestId,record);
    void session.send('Network.streamResourceContent',{requestId:event.requestId}).then(result=>{
      if(result.bufferedData)record.chunks.unshift(Buffer.from(result.bufferedData,'base64'));
      record.ready=true;
    }).catch(error=>{record.error=String(error.message);record.ready=true;});
  });
  session.on('Network.dataReceived',event=>{
    const record=records.get(event.requestId);if(record&&event.data)record.chunks.push(Buffer.from(event.data,'base64'));
  });
  for(const name of ['Network.loadingFinished','Network.loadingFailed'])session.on(name,event=>{
    const record=records.get(event.requestId);if(record)record.ended=true;
  });
  await session.send('Network.enable');
  return {
    async body(response) {
      const deadline=Date.now()+240000;
      while(Date.now()<deadline){
        const record=[...records.values()].find(record=>record.url===response.url());
        if(record?.ready){
          const bytes=Buffer.concat(record.chunks);
          const terminal=bytes.toString('utf8').split(/\r?\n/).some(line=>{
            try{const event=JSON.parse(line.replace(/^data:\s*/,''));return ['done','error'].includes(event.type)&&!event.data?.recorded&&event.data?.eventTiming!=='VERIFIED_RECORD';}catch{return false;}
          });
          if(terminal)return bytes;
          if(record.ended){if(bytes.length)return bytes;return response.body();}
        }
        await pause(25);
      }
      throw new Error('AI response capture did not receive a terminal event within 240 seconds');
    },
    async close(){await session.detach();},
  };
};
