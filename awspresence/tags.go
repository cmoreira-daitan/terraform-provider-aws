package awspresence

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

// tagsSchema returns the schema to use for tags.
//
func tagsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Optional: true,
	}
}

func tagsSchemaComputed() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Optional: true,
		Computed: true,
	}
}

func setElbV2Tags(conn *elbv2.ELBV2, d *schema.ResourceData) error {
	if d.HasChange("tags") {
		oraw, nraw := d.GetChange("tags")
		o := oraw.(map[string]interface{})
		n := nraw.(map[string]interface{})
		create, remove := diffElbV2Tags(tagsFromMapELBv2(o), tagsFromMapELBv2(n))

		// Set tags
		if len(remove) > 0 {
			var tagKeys []*string
			for _, tag := range remove {
				tagKeys = append(tagKeys, tag.Key)
			}
			log.Printf("[DEBUG] Removing tags: %#v from %s", remove, d.Id())
			_, err := conn.RemoveTags(&elbv2.RemoveTagsInput{
				ResourceArns: []*string{aws.String(d.Id())},
				TagKeys:      tagKeys,
			})
			if err != nil {
				return err
			}
		}
		if len(create) > 0 {
			log.Printf("[DEBUG] Creating tags: %s for %s", create, d.Id())
			_, err := conn.AddTags(&elbv2.AddTagsInput{
				ResourceArns: []*string{aws.String(d.Id())},
				Tags:         create,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// setTags is a helper to set the tags for a resource. It expects the
// tags field to be named "tags"
func setTags(conn *ec2.EC2, d *schema.ResourceData) error {
	if d.HasChange("tags") {
		oraw, nraw := d.GetChange("tags")
		o := oraw.(map[string]interface{})
		n := nraw.(map[string]interface{})
		create, remove := diffTags(tagsFromMap(o), tagsFromMap(n))

		// Set tags
		if len(remove) > 0 {
			err := resource.Retry(5*time.Minute, func() *resource.RetryError {
				log.Printf("[DEBUG] Removing tags: %#v from %s", remove, d.Id())
				_, err := conn.DeleteTags(&ec2.DeleteTagsInput{
					Resources: []*string{aws.String(d.Id())},
					Tags:      remove,
				})
				if err != nil {
					ec2err, ok := err.(awserr.Error)
					if ok && strings.Contains(ec2err.Code(), ".NotFound") {
						return resource.RetryableError(err) // retry
					}
					return resource.NonRetryableError(err)
				}
				return nil
			})
			if err != nil {
				// Retry without time bounds for EC2 throttling
				if isResourceTimeoutError(err) {
					log.Printf("[DEBUG] Removing tags: %#v from %s", remove, d.Id())
					_, err := conn.DeleteTags(&ec2.DeleteTagsInput{
						Resources: []*string{aws.String(d.Id())},
						Tags:      remove,
					})
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}
		if len(create) > 0 {
			err := resource.Retry(5*time.Minute, func() *resource.RetryError {
				log.Printf("[DEBUG] Creating tags: %s for %s", create, d.Id())
				_, err := conn.CreateTags(&ec2.CreateTagsInput{
					Resources: []*string{aws.String(d.Id())},
					Tags:      create,
				})
				if err != nil {
					ec2err, ok := err.(awserr.Error)
					if ok && strings.Contains(ec2err.Code(), ".NotFound") {
						return resource.RetryableError(err) // retry
					}
					return resource.NonRetryableError(err)
				}
				return nil
			})
			if err != nil {
				// Retry without time bounds for EC2 throttling
				if isResourceTimeoutError(err) {
					log.Printf("[DEBUG] Creating tags: %s for %s", create, d.Id())
					_, err := conn.CreateTags(&ec2.CreateTagsInput{
						Resources: []*string{aws.String(d.Id())},
						Tags:      create,
					})
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}
	}

	return nil
}

// diffTags takes our tags locally and the ones remotely and returns
// the set of tags that must be created, and the set of tags that must
// be destroyed.
func diffTags(oldTags, newTags []*ec2.Tag) ([]*ec2.Tag, []*ec2.Tag) {
	// First, we're creating everything we have
	create := make(map[string]interface{})
	for _, t := range newTags {
		create[aws.StringValue(t.Key)] = aws.StringValue(t.Value)
	}

	// Build the list of what to remove
	var remove []*ec2.Tag
	for _, t := range oldTags {
		old, ok := create[aws.StringValue(t.Key)]
		if !ok || old != aws.StringValue(t.Value) {
			remove = append(remove, t)
		} else if ok {
			// already present so remove from new
			delete(create, aws.StringValue(t.Key))
		}
	}

	return tagsFromMap(create), remove
}

// tagsFromMap returns the tags for the given map of data.
func tagsFromMap(m map[string]interface{}) []*ec2.Tag {
	result := make([]*ec2.Tag, 0, len(m))
	for k, v := range m {
		t := &ec2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v.(string)),
		}
		if !tagIgnored(t) {
			result = append(result, t)
		}
	}

	return result
}

// tagsToMap turns the list of tags into a map.
func tagsToMap(ts []*ec2.Tag) map[string]string {
	result := make(map[string]string)
	for _, t := range ts {
		if !tagIgnored(t) {
			result[*t.Key] = *t.Value
		}
	}

	return result
}

func diffElbV2Tags(oldTags, newTags []*elbv2.Tag) ([]*elbv2.Tag, []*elbv2.Tag) {
	// First, we're creating everything we have
	create := make(map[string]interface{})
	for _, t := range newTags {
		create[*t.Key] = *t.Value
	}

	// Build the list of what to remove
	var remove []*elbv2.Tag
	for _, t := range oldTags {
		old, ok := create[*t.Key]
		if !ok || old != *t.Value {
			// Delete it!
			remove = append(remove, t)
		}
	}

	return tagsFromMapELBv2(create), remove
}

// tagsToMapELBv2 turns the list of tags into a map.
func tagsToMapELBv2(ts []*elbv2.Tag) map[string]string {
	result := make(map[string]string)
	for _, t := range ts {
		if !tagIgnoredELBv2(t) {
			result[*t.Key] = *t.Value
		}
	}

	return result
}

// tagsFromMapELBv2 returns the tags for the given map of data.
func tagsFromMapELBv2(m map[string]interface{}) []*elbv2.Tag {
	var result []*elbv2.Tag
	for k, v := range m {
		t := &elbv2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v.(string)),
		}
		if !tagIgnoredELBv2(t) {
			result = append(result, t)
		}
	}

	return result
}

// tagIgnored compares a tag against a list of strings and checks if it should
// be ignored or not
func tagIgnored(t *ec2.Tag) bool {
	filter := []string{"^aws:"}
	for _, v := range filter {
		log.Printf("[DEBUG] Matching %v with %v\n", v, *t.Key)
		r, _ := regexp.MatchString(v, *t.Key)
		if r {
			log.Printf("[DEBUG] Found AWS specific tag %s (val: %s), ignoring.\n", *t.Key, *t.Value)
			return true
		}
	}
	return false
}

// and for ELBv2 as well
func tagIgnoredELBv2(t *elbv2.Tag) bool {
	filter := []string{"^aws:"}
	for _, v := range filter {
		log.Printf("[DEBUG] Matching %v with %v\n", v, *t.Key)
		r, _ := regexp.MatchString(v, *t.Key)
		if r {
			log.Printf("[DEBUG] Found AWS specific tag %s (val: %s), ignoring.\n", *t.Key, *t.Value)
			return true
		}
	}
	return false
}

// tagsMapToHash returns a stable hash value for a raw tags map.
// The returned value map be negative (i.e. not suitable for a 'Set' function).
func tagsMapToHash(tags map[string]interface{}) int {
	total := 0
	for k, v := range tags {
		total = total ^ hashcode.String(fmt.Sprintf("%s-%s", k, v))
	}
	return total
}

// tagsMapToRaw converts a tags map to its "raw" type.
func tagsMapToRaw(m map[string]string) map[string]interface{} {
	raw := make(map[string]interface{})
	for k, v := range m {
		raw[k] = v
	}

	return raw
}

// ec2TagSpecificationsFromMap returns the tag specifications for the given map of data m and resource type t.
func ec2TagSpecificationsFromMap(m map[string]interface{}, t string) []*ec2.TagSpecification {
	if len(m) == 0 {
		return nil
	}

	return []*ec2.TagSpecification{
		{
			ResourceType: aws.String(t),
			Tags:         tagsFromMap(m),
		},
	}
}
