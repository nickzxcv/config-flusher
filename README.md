# config-flusher
Sends purge/invalidation/flush requests for a file/files hosted on 3 CDNs.

At work we have some config files hosted on CDNs for different customers using our software. We use Amazon Cloudfront, Level3, and Edgecast (now known as Verizon Digital Media Services).

This program uses Linux inotify to watch a directory for a certain file being updated. This is the source file for all the customer configs, so when it gets updated the program starts checking for the new version appearing for a default customer on our CDN origin. When that appears, the CDN will be able to get the new version so it sends the flush requests out to get rid of the old ones.

It also provides a status API over HTTP, so a monitoring system can tell if the program is stuck or is not getting updates.
