#!/usr/bin/python

import json
import requests
import re
import sys
import hashlib
from rauth import OAuth1Session,OAuth1Service

API_ORIGIN = 'https://api.smugmug.com'


key=None
secret=None
access_token=None
access_token_secret=None

# oauth:
# http://api.smugmug.com/services/oauth/1.0a/getRequestToken
#   oauth_callback=oob (no redirect)

class Smugger:
  def getAccessToken(self):
    # cribbed from the example, obviously:
    # https://api.smugmug.com/api/v2/doc/tutorial/oauth/non-web.html
    service = OAuth1Service(
      name='tedder-python',
      consumer_key=key,
      consumer_secret=secret,
      request_token_url='http://api.smugmug.com/services/oauth/1.0a/getRequestToken',
      authorize_url='http://api.smugmug.com/services/oauth/1.0a/authorize',
      access_token_url='http://api.smugmug.com/services/oauth/1.0a/getAccessToken',
      base_url=API_ORIGIN + '/api/v2')

    rt, rts = service.get_request_token(params={'oauth_callback': 'oob'})
    auth_url = service.get_authorize_url(rt) + '&Access=Full&Permissions=Modify'
    print('Go to the following url in a web browser:\n{}'.format(auth_url))

    sys.stdout.write('Enter the six-digit code: ')
    sys.stdout.flush()
    verifier = sys.stdin.readline().strip()

    access_token, access_token_secret = service.get_access_token(rt, rts, params={'oauth_verifier': verifier})
    print('Access token: %s' % access_token)
    print('Access token secret: %s' % access_token_secret)

  session = None
  def getSession(self):
    if self.session: return self.session
    if not access_token or not access_token_secret:
      # check for --console tag or something that says we shouldn't use stdin
      print('no token, so getting one.')
      self.getAccessToken()
      print('put those in the file.')
      sys.exit(-1)

    self.session = OAuth1Session(key, secret, access_token=access_token, access_token_secret=access_token_secret)

    # print(session.get(
    #    API_ORIGIN + '/api/v2!authuser',
    #    headers={'Accept': 'application/json'}).text)
    return self.session

  def getAlbums():
    return self.doCall('api/v2/album', { 'empty': False, 'NickName': 'tedder' })
    #session.get(/do

  #def getFolders(username='tedder', folder_name=''):
  #  '/api/v2/folder/user/' + username + 

  def findAlbum(self, url):
    albums = self.doCall("smugmug.albums.get", { 'Empty': False, 'NickName': 'tedder', 'Extras': 'URL' })
    for album in albums['Albums']:
      if album.get('URL') == url:
        return album
    return None

# http://api.smugmug.com/services/api/?version=1.3.0&method=smugmug.images.getURLs
# note CustomSize, LightboxUrl
  def getAlbumImages(self, album_url):
    album_data = self.findAlbum(album_url)
    album_images = self.doCall("smugmug.images.get", { 'AlbumID': album_data['id'], 'AlbumKey': album_data['Key'], 'Extras': 'URL,Caption,FileName' })
    #print "foo: %s" % album_images
    for image in album_images['Album']['Images']:
      #print image
      #sys.exit(0)
      #print "this: %s" % image
      image_ret = {}
      image_ret['url'] = image['URL']
      image_ret['caption'] = image['Caption']
      image_ret['filename'] = re.sub(r'\.jpg', '', image['FileName'].lower())
      if image_ret['caption']:
        # strip html; http://stackoverflow.com/a/19730306/659298
        image_ret['filename'] = re.sub(r'(<!--.*?-->|<[^>]*>)', '', image_ret['caption'])
        # convert random stuff to underscores
        image_ret['filename'] = re.sub(r'[^\w]+', '_', image_ret['filename'])
      image_ret['thumb'] = "%s/0/1000x1000!/%s-1000.jpg" % (image_ret['url'], image_ret['filename'])
      image_ret['full'] = "%s/0/X2/%s-X2.jpg" % (image_ret['url'], image_ret['filename'])
      print """
<a href="{0[full]}" data-lightbox="main" data-title="{0[caption]}"><img src="{0[thumb]}" class="img-thumbnail" /></a>
<legend>{0[caption]}</legend>
""".format(image_ret)
      # css to render captions: http://cssdeck.com/labs/awesome-image-captions-with-css
      print """
[![{0[caption]}]({0[thumb]} "{0[caption]}")]({0[full]})
""".format(image_ret)
    pass

  #def login():
    #doCall(

  userdata = None
  def getUser(self):
    if self.userdata: return self.userdata
    self.userdata = self.doCall('/api/v2!authuser')
    return self.userdata

  def doCall(self, method, payload={}):
    session = self.getSession()
    ret = session.get(
      API_ORIGIN + method,
      params=payload,
      headers={'Accept': 'application/json'}
    ).json()

  def doOldCall(self, method, payload):
    url = 'http://api.smugmug.com/services/api/json/1.3.0/'
    payload['APIKey'] = key
    payload['Pretty'] = True
    payload['method'] = method
    #payload['SessionID'] = secret
    #payload = { 'APIKey': 
    req = requests.get(url, params=payload)
    #print "fetched url: %s" % req.url
    return req.json()


# http://api.smugmug.com/services/api/?version=1.3.0&method=smugmug.images.getInfo
# 

  def upload(filepath):
    # http://api.smugmug.com/services/api/?method=upload&version=1.3.0
    fstat = os.stat(filepath)
    filename = os.path.basename(filepath)
    hash_md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    file_md5 = hash_md5.hexdigest()
 
    params = {
      filenameSize: fstat.ST_SIZE,
      filenameMD5: file_md5,
      'X-Smug-AlbumID': None,
      'X-Smug-Caption': None,
      'X-Smug-Pretty': true,
      'X-Smug-SessionID': None,
      'X-Smug-Version': '1.3.0'
    }
    requests.put('http://upload.smugmug.com/test.jpg')

    payload['APIKey'] = key
    payload['Pretty'] = True
    payload['method'] = method
    #payload['SessionID'] = secret
    #payload = { 'APIKey': 
    req = requests.get(url, params=payload)
    #print "fetched url: %s" % req.url
    return req.json()

#Smugger().getAlbumImages('http://pix.perljam.net/Travel/Europe-2014/Day1')
#print(Smugger().getAlbums())
print ("hello world")
smugger = Smugger()
# need to get user so we can get the nodes, which are the new way to do categories.
# https://api.smugmug.com/api/v2/doc/reference/user.html
print(smugger.getUser())

