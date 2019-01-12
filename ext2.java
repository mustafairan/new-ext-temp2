package burp;

import java.io.PrintWriter;
import java.util.Random;
import java.util.List;


public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private int counter = 0;
    private int padding= 8;
    private int startvalue = 18521; //start value // will be override


    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("cacheier");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        findAndIncrement(messageIsRequest,messageInfo);
        findAllInstancesOfAHeaderAndRemove2(messageIsRequest,messageInfo,"Cache-Control");
    }


    public void findAndIncrement (boolean messageIsRequest, burp.IHttpRequestResponse messageInfo){
        boolean updated = false;

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());
            List<String> headers = iRequest.getHeaders();

            String reqBody = request.substring(iRequest.getBodyOffset());

            if (reqBody.contains("IncrementMePlease")) {

                int offset = reqBody.indexOf("IncrementMePlease");
                String starter=reqBody.substring(offset+17,offset+17+padding);
                startvalue=Integer.parseInt(starter);
                reqBody = reqBody.replaceAll("IncrementMePlease"+starter,  String.valueOf(startvalue+counter));
                counter++;
                updated = true;
            }

            if (updated) {
                stdout.println("request updated");
                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

            }
        }


        return;
    }
    public void findAllInstancesOfAHeaderAndRemove2 (boolean messageIsRequest, burp.IHttpRequestResponse messageInfo,String headersName){

        boolean updated = false;
        burp.IHttpService httpService = messageInfo.getHttpService();
        burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

        String request = new String(messageInfo.getRequest());
        String reqBody = request.substring(iRequest.getBodyOffset());
        List<String> headers = iRequest.getHeaders();
        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request


            for (int i = 0; i < headers.size(); i++) {
                if (((String) headers.get(i)).startsWith(headersName+": ")) {
                    // there could be more than one header like this; remove and continue
                    headers.remove(i);
                    updated = true;
                }
            }

        }

        if (updated) {
            stdout.println("request updated and header deletedu");
            byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
            messageInfo.setRequest(message);

        }

        return ;
    }
    public List<String> findAllInstancesOfAHeaderAndRemove (List<String> headers){


        for (int i = 0; i < headers.size(); i++) {
            if (((String) headers.get(i)).startsWith("Cache-Control"+": ")) {
                // there could be more than one header like this; remove and continue
                headers.remove(i);
            }
        }


        stdout.println("findAllInstancesOfAHeader did nothing");

        return headers ;

    }

}
